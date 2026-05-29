"""
resolver-service/main.py — Firmware Sentry Symbol Resolver Microservice

FastAPI service that wraps pyelftools DWARF resolution.
Deploy on Railway (free tier) — stays warm, no cold start penalty.

Vercel calls this at crash ingest time when elf_uploaded=true.
Returns resolved symbols → Vercel passes to Claude → better AI diagnosis.

Environment variables (set in Railway dashboard):
    SUPABASE_URL             — from Supabase project settings
    SUPABASE_SERVICE_KEY     — service role key (not anon key)
    RESOLVER_SECRET          — random string, set same in Vercel as RESOLVER_SECRET
"""

import os
import tempfile
import struct
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from elftools.elf.elffile import ELFFile
from supabase import create_client

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL    = os.environ['SUPABASE_URL']
SUPABASE_KEY    = os.environ['SUPABASE_SERVICE_KEY']
RESOLVER_SECRET = os.environ.get('RESOLVER_SECRET', '')

# Stdlib file patterns — these appear when DWARF resolves to an inlined
# standard library call rather than the actual application source line.
# We keep the function name but clear the misleading file/line.
STDLIB_PATTERNS = [
    'svfiprintf', 'printf', 'vfprintf', 'fprintf', 'sprintf',
    'libc', 'newlib', 'stdio', 'string', 'malloc', 'reent',
    'vsnprintf', 'snprintf', 'puts', 'fputs',
]

app = FastAPI(title="Firmware Sentry Symbol Resolver", version="1.0.0")

# ── Auth ──────────────────────────────────────────────────────────────────────

def verify_secret(x_resolver_secret: str = Header(default='')):
    if RESOLVER_SECRET and x_resolver_secret != RESOLVER_SECRET:
        raise HTTPException(status_code=401, detail='Invalid resolver secret')
    return True

# ── Request / Response models ─────────────────────────────────────────────────

class ResolveRequest(BaseModel):
    crash_id:         str
    org_id:           str
    pc:               str
    lr:               Optional[str] = None
    stack_data:       Optional[str] = None
    build_hash:       str
    firmware_version: str
    group_id:         Optional[str] = None
    platform:         str = 'esp32'

class ResolvedSymbol(BaseModel):
    address:  str
    function: Optional[str]
    file:     Optional[str]
    line:     Optional[int]

class ResolveResponse(BaseModel):
    resolved:      bool
    reason:        Optional[str]            = None
    pc:            Optional[ResolvedSymbol] = None
    lr:            Optional[ResolvedSymbol] = None
    call_chain:    list                     = []
    stack_strings: list                     = []

# ── ELF download ──────────────────────────────────────────────────────────────

def download_elf(org_id: str, group_id: Optional[str],
                 firmware_version: str, build_hash: str) -> Optional[str]:
    """
    Download ELF from Supabase Storage.
    Tries paths in order:
      1. org/group_id/build_hash.elf          (group-specific, most specific)
      2. org/firmware_version/build_hash.elf  (version-based fallback)
      3. Org-wide search across all group folders (catches mismatched group)
    Returns temp file path or None.
    """
    sb = create_client(SUPABASE_URL, SUPABASE_KEY)

    # Specific paths first
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
            print(f"[resolver] Path not found: {path} — {e}")
            continue

    # Org-wide search — handles build_hash stored under a different group
    try:
        folders = sb.storage.from_('elf-files').list(org_id)
        for folder in (folders or []):
            candidate = f"{org_id}/{folder['name']}/{build_hash}.elf"
            try:
                data = sb.storage.from_('elf-files').download(candidate)
                tmp = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
                tmp.write(data)
                tmp.close()
                print(f"[resolver] Found via org-wide search: {candidate} ({len(data):,} bytes)")
                return tmp.name
            except Exception:
                continue
    except Exception as e:
        print(f"[resolver] Org-wide search failed: {e}")

    return None

# ── Core DWARF resolver ───────────────────────────────────────────────────────

def resolve_address(elf_path: str, addr: int) -> dict:
    """Resolve address → function/file/line using DWARF."""
    result = {'address': f'0x{addr:08X}', 'function': None, 'file': None, 'line': None}

    # Strip Thumb bit (ARM Cortex-M) and CALL8 encoding (Xtensa ESP32)
    clean   = addr & ~1           # strip Thumb bit
    xtensa  = addr & 0x3FFFFFFF   # strip Xtensa CALL8 top 2 bits

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)

        if elf.has_dwarf_info():
            dwarf = elf.get_dwarf_info()

            # 1. DWARF .debug_info — function name via DW_TAG_subprogram
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

            # 2. DWARF .debug_line — file and line number
            for CU in dwarf.iter_CUs():
                try:
                    li = dwarf.line_program_for_CU(CU)
                    if li is None:
                        continue
                    prev = None
                    for entry in li.get_entries():
                        if entry.state is None:
                            continue
                        if prev and (prev.address <= clean  < entry.state.address or
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

        # 3. Filter stdlib inlined frames — keep function name, clear misleading file/line
        #    e.g. svfiprintf.c:2344 appears when printf is inlined into app_main()
        if result['file'] and any(p in result['file'].lower() for p in STDLIB_PATTERNS):
            result['file'] = None
            result['line'] = None

        # 4. Fallback — symbol table (.symtab) when DWARF has no debug_info
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

# ── Stack analysis ────────────────────────────────────────────────────────────

def analyse_stack(stack_hex: str, platform: str) -> dict:
    """Extract flash addresses and ASCII strings from raw stack dump."""
    if platform == 'esp32':
        flash_lo, flash_hi = 0x400C0000, 0x40280000
    else:   # cortex_m
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

    strings, current = [], []
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

# ── API endpoints ─────────────────────────────────────────────────────────────

@app.get('/health')
def health():
    return {'status': 'ok', 'service': 'firmware-sentry-resolver'}


@app.post('/resolve', response_model=ResolveResponse)
def resolve(req: ResolveRequest, _auth=Depends(verify_secret)):
    print(f"[resolver] crash={req.crash_id}  build={req.build_hash}  pc={req.pc}")

    # 1. Download ELF
    elf_path = download_elf(req.org_id, req.group_id, req.firmware_version, req.build_hash)
    if not elf_path:
        print(f"[resolver] No ELF found for build_hash={req.build_hash}")
        return ResolveResponse(resolved=False, reason='ELF not found for this build_hash')

    try:
        # 2. Resolve PC
        pc_int      = int(req.pc, 16)
        pc_resolved = resolve_address(elf_path, pc_int)
        print(f"[resolver] PC {req.pc} → {pc_resolved['function'] or '?'} "
              f"at {pc_resolved['file'] or '?'}:{pc_resolved['line'] or '?'}")

        # 3. Resolve LR
        lr_resolved = None
        if req.lr:
            try:
                lr_resolved = resolve_address(elf_path, int(req.lr, 16))
                print(f"[resolver] LR {req.lr} → {lr_resolved['function'] or '?'}")
            except Exception as e:
                print(f"[resolver] LR resolve failed: {e}")

        # 4. Stack analysis — call chain + strings
        call_chain, stack_strings = [], []
        if req.stack_data:
            analysis     = analyse_stack(req.stack_data, req.platform)
            stack_strings = analysis['strings']
            for entry in analysis['flash_addresses'][:8]:
                resolved = resolve_address(elf_path, entry['value'])
                if resolved['function']:
                    call_chain.append({**resolved, 'stack_offset': entry['offset']})

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
        try:
            os.unlink(elf_path)
        except Exception:
            pass