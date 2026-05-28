"""
resolver-service/main.py — Firmware Sentry Symbol Resolver Microservice

FastAPI service that wraps pyelftools DWARF resolution.
Deploy on Railway (free tier) — stays warm, no cold start penalty.

Vercel calls this at crash ingest time when elf_uploaded=true.
Returns resolved symbols → Vercel passes to Claude → better AI diagnosis.

Deploy:
    railway new
    railway add  (select this directory)
    railway up

Environment variables (set in Railway dashboard):
    SUPABASE_URL             — from Supabase project settings
    SUPABASE_SERVICE_KEY     — service role key (not anon key)
    RESOLVER_SECRET          — random string, set same in Vercel as RESOLVER_SECRET

Usage:
    POST /resolve
    {
        "crash_id": "uuid",
        "org_id":   "uuid",
        "pc":       "0x400D9741",
        "lr":       "0x4016B67F",
        "stack_data": "...",          (optional)
        "build_hash": "dadf1fb9",
        "firmware_version": "1.0.0",
        "group_id": "uuid",
        "platform": "esp32"           (or "cortex_m")
    }

    Response 200:
    {
        "resolved": true,
        "pc": { "function": "app_main", "file": "main.c", "line": 148, "address": "0x400D9741" },
        "lr": { "function": "main_task", "file": "app_startup.c", "line": 208, "address": "0x4016B67F" },
        "call_chain": [ ... ],
        "stack_strings": [ ... ]
    }

    Response 200 (no ELF):
    { "resolved": false, "reason": "ELF not found" }
"""

import os
import tempfile
import struct
import json
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import uvicorn

from elftools.elf.elffile import ELFFile
from supabase import create_client

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL     = os.environ['SUPABASE_URL']
SUPABASE_KEY     = os.environ['SUPABASE_SERVICE_KEY']
RESOLVER_SECRET  = os.environ.get('RESOLVER_SECRET', '')   # shared secret with Vercel

app = FastAPI(title="Firmware Sentry Symbol Resolver", version="1.0.0")

# ── Auth ──────────────────────────────────────────────────────────────────────

def verify_secret(x_resolver_secret: str = Header(default='')):
    if RESOLVER_SECRET and x_resolver_secret != RESOLVER_SECRET:
        raise HTTPException(status_code=401, detail='Invalid resolver secret')
    return True

# ── Request/Response models ───────────────────────────────────────────────────

class ResolveRequest(BaseModel):
    crash_id:         str
    org_id:           str
    pc:               str
    lr:               Optional[str]  = None
    stack_data:       Optional[str]  = None
    build_hash:       str
    firmware_version: str
    group_id:         Optional[str]  = None
    platform:         str            = 'esp32'

class ResolvedSymbol(BaseModel):
    address:  str
    function: Optional[str]
    file:     Optional[str]
    line:     Optional[int]

class ResolveResponse(BaseModel):
    resolved:      bool
    reason:        Optional[str]   = None
    pc:            Optional[ResolvedSymbol] = None
    lr:            Optional[ResolvedSymbol] = None
    call_chain:    list            = []
    stack_strings: list            = []

# ── ELF download ──────────────────────────────────────────────────────────────

def download_elf(org_id: str, group_id: Optional[str],
                 firmware_version: str, build_hash: str) -> Optional[str]:
    """Download ELF from Supabase Storage. Returns temp file path or None."""
    sb = create_client(SUPABASE_URL, SUPABASE_KEY)

    paths = []
    if group_id:
        paths.append(f"{org_id}/{group_id}/{build_hash}.elf")
    paths.append(f"{org_id}/{firmware_version}/{build_hash}.elf")

    for path in paths:
        try:
            data = sb.storage.from_('elf-files').download(path)
            tmp = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
            tmp.write(data)
            tmp.close()
            print(f"[resolver] ELF downloaded: {path} ({len(data):,} bytes)")
            return tmp.name
        except Exception as e:
            print(f"[resolver] ELF path not found: {path} — {e}")
            continue

    return None

# ── Core DWARF resolver ───────────────────────────────────────────────────────

def resolve_address(elf_path: str, addr: int) -> dict:
    """Resolve address → function/file/line using DWARF."""
    result = {'address': f'0x{addr:08X}', 'function': None, 'file': None, 'line': None}

    # Strip Thumb bit (ARM) and CALL8 encoding (Xtensa)
    clean = addr & ~1          # strip Thumb bit
    xtensa = addr & 0x3FFFFFFF  # strip Xtensa CALL8 top 2 bits

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)

        # 1. Try DWARF .debug_info for function name
        if elf.has_dwarf_info():
            dwarf = elf.get_dwarf_info()
            for CU in dwarf.iter_CUs():
                for DIE in CU.iter_DIEs():
                    if DIE.tag != 'DW_TAG_subprogram':
                        continue
                    try:
                        low  = DIE.attributes.get('DW_AT_low_pc')
                        high = DIE.attributes.get('DW_AT_high_pc')
                        name = DIE.attributes.get('DW_AT_name')
                        if not (low and high and name):
                            continue
                        lo = low.value
                        hi = high.value if high.form == 'DW_FORM_addr' else lo + high.value
                        if lo <= clean < hi or lo <= xtensa < hi:
                            result['function'] = name.value.decode('utf-8', errors='replace')
                    except Exception:
                        continue

            # 2. Try DWARF .debug_line for file/line
            for CU in dwarf.iter_CUs():
                try:
                    li = dwarf.line_program_for_CU(CU)
                    if li is None:
                        continue
                    prev = None
                    for entry in li.get_entries():
                        if entry.state is None:
                            continue
                        if prev and (prev.address <= clean < entry.state.address or
                                     prev.address <= xtensa < entry.state.address):
                            lp = li.header
                            fi = lp.file_entry[prev.file - 1]
                            fname = fi.name.decode('utf-8', errors='replace')
                            if fi.dir_index > 0:
                                d = lp.include_directory[fi.dir_index - 1]
                                fname = d.decode('utf-8', errors='replace').split('/')[-1] + '/' + fname
                            result['file'] = fname.split('/')[-1]   # basename only
                            result['line'] = prev.line
                            break
                        prev = entry.state
                except Exception:
                    continue

        # 3. Fallback: symbol table
        if result['function'] is None:
            symtab = elf.get_section_by_name('.symtab')
            if symtab:
                best = None
                for sym in symtab.iter_symbols():
                    if sym['st_info']['type'] not in ('STT_FUNC', 'STT_NOTYPE'):
                        continue
                    saddr = sym['st_value']
                    ssize = sym['st_size']
                    if saddr <= clean < saddr + max(ssize, 1):
                        if best is None or ssize < best[1]:
                            best = (sym.name, ssize)
                if best:
                    result['function'] = best[0]

    return result


def analyse_stack(stack_hex: str, platform: str) -> dict:
    """Extract flash addresses and ASCII strings from raw stack dump."""
    # Flash address ranges
    if platform == 'esp32':
        flash_lo, flash_hi = 0x400C0000, 0x40280000
    else:  # cortex_m
        flash_lo, flash_hi = 0x08000000, 0x08200000

    try:
        raw = bytes.fromhex(stack_hex)
    except ValueError:
        return {'flash_addresses': [], 'strings': []}

    flash_addrs = []
    for i in range(0, len(raw) - 3, 4):
        val = struct.unpack_from('<I', raw, i)[0]
        if flash_lo <= val < flash_hi:
            flash_addrs.append({'offset': i, 'value': val})

    # Extract printable strings ≥4 chars
    strings = []
    current = []
    for byte in raw:
        if 0x20 <= byte < 0x7F:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                strings.append(''.join(current))
            current = []
    if len(current) >= 4:
        strings.append(''.join(current))

    return {'flash_addresses': flash_addrs[:16], 'strings': strings[:8]}

# ── API endpoint ──────────────────────────────────────────────────────────────

@app.get('/health')
def health():
    return {'status': 'ok', 'service': 'firmware-sentry-resolver'}


@app.post('/resolve', response_model=ResolveResponse)
def resolve(req: ResolveRequest, _auth=Depends(verify_secret)):
    print(f"[resolver] crash={req.crash_id}  build={req.build_hash}  pc={req.pc}")

    # 1. Download ELF
    elf_path = download_elf(
        req.org_id, req.group_id, req.firmware_version, req.build_hash
    )
    if not elf_path:
        print(f"[resolver] No ELF found for build {req.build_hash}")
        return ResolveResponse(resolved=False, reason='ELF not found for this build_hash')

    try:
        # 2. Resolve PC
        pc_int = int(req.pc, 16)
        pc_resolved = resolve_address(elf_path, pc_int)
        print(f"[resolver] PC {req.pc} → {pc_resolved['function'] or '?'} "
              f"{pc_resolved['file'] or '?'}:{pc_resolved['line'] or '?'}")

        # 3. Resolve LR
        lr_resolved = None
        if req.lr:
            try:
                lr_int = int(req.lr, 16)
                lr_resolved = resolve_address(elf_path, lr_int)
                print(f"[resolver] LR {req.lr} → {lr_resolved['function'] or '?'}")
            except Exception as e:
                print(f"[resolver] LR resolve failed: {e}")

        # 4. Stack analysis + call chain
        call_chain = []
        stack_strings = []
        if req.stack_data:
            stack_analysis = analyse_stack(req.stack_data, req.platform)
            stack_strings = stack_analysis['strings']
            for entry in stack_analysis['flash_addresses'][:8]:
                resolved = resolve_address(elf_path, entry['value'])
                if resolved['function']:   # only include if resolved
                    call_chain.append({
                        **resolved,
                        'stack_offset': entry['offset'],
                    })

        return ResolveResponse(
            resolved=True,
            pc=ResolvedSymbol(**pc_resolved) if pc_resolved else None,
            lr=ResolvedSymbol(**lr_resolved) if lr_resolved else None,
            call_chain=call_chain,
            stack_strings=stack_strings,
        )

    except Exception as e:
        print(f"[resolver] Resolution failed: {e}")
        return ResolveResponse(resolved=False, reason=str(e))

    finally:
        # Clean up temp ELF file
        try:
            os.unlink(elf_path)
        except Exception:
            pass


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    uvicorn.run('main:app', host='0.0.0.0', port=port, workers=2)
