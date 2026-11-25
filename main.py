"""
resolver-service/main.py — Firmware Sentry Symbol Resolver Microservice

FastAPI service wrapping pyelftools DWARF resolution with inline frame walking.
Deploy on Railway — stays warm, no cold start penalty.

Environment variables:
    SUPABASE_URL         — Supabase project URL
    SUPABASE_SERVICE_KEY — service role key
    RESOLVER_SECRET      — shared secret with Vercel
"""

import os
import tempfile
import struct
import subprocess
import re
import hmac
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from supabase import create_client

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL    = os.environ['SUPABASE_URL']
SUPABASE_KEY    = os.environ['SUPABASE_SERVICE_KEY']
RESOLVER_SECRET = os.environ.get('RESOLVER_SECRET', '')

# Patterns to filter from file/line results.
# These appear when DWARF resolves to inlined stdlib or IDF internal frames
# rather than the actual application source line.
STDLIB_PATTERNS = [
    # C stdlib
    'svfiprintf', 'printf', 'vfprintf', 'fprintf', 'sprintf',
    'libc', 'newlib', 'stdio', 'string', 'malloc', 'reent',
    'vsnprintf', 'snprintf', 'puts', 'fputs',
    # ESP-IDF internals
    'esp_app_desc', 'esp_system', 'esp_common', 'esp_hw_support',
    'esp_efuse', 'efuse', 'esp_phy', 'esp_wifi', 'esp_partition',
    'esp_flash', 'spi_flash', 'nvs_flash', 'esp_https',
    'esp_rom', 'soc', 'hal/', 'esp_event', 'esp_netif',
    'freertos', 'FreeRTOS', 'port.c', 'tasks.c', 'queue.c',
    'app_startup', 'cpu_start', 'startup',
]

app = FastAPI(title="Firmware Sentry Symbol Resolver", version="1.0.0")

# ── Auth ──────────────────────────────────────────────────────────────────────

def verify_secret(x_resolver_secret: str = Header(default='')):
    # Never turn off authentication accidentally by omitting the secret.
    if not RESOLVER_SECRET or not hmac.compare_digest(x_resolver_secret, RESOLVER_SECRET):
        raise HTTPException(status_code=401, detail='Invalid resolver secret')
    return True

# ── Models ────────────────────────────────────────────────────────────────────

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

# ── ELF cache — persists between requests (Railway is always-on) ─────────────
import threading
_elf_cache: dict = {}          # (org, group, version, build) → temp path
_elf_cache_lock = threading.Lock()
_ELF_CACHE_MAX = 1             # keep at most 3 ELFs in memory

# ── ELF download ──────────────────────────────────────────────────────────────

def _download_elf_raw(org_id: str, group_id: Optional[str],
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
            print(f"[resolver] Path not found: {path} — {e}")
            continue

    # No org-wide fallback: it could use the wrong firmware version's ELF.
    return None


def download_elf(org_id: str, group_id: Optional[str],
                 firmware_version: str, build_hash: str) -> Optional[str]:
    """Return cached ELF path or download fresh. Cache survives between requests."""
    # Prevent cross-tenant cache matches and path manipulation.
    for segment in (org_id, firmware_version, build_hash):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", segment) or ".." in segment:
            raise ValueError("Invalid ELF storage path segment")
    if group_id is not None and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", group_id) or ".." in group_id):
        raise ValueError("Invalid group identifier")
    cache_key = (org_id, group_id, firmware_version, build_hash)
    with _elf_cache_lock:
        if cache_key in _elf_cache:
            cached = _elf_cache[cache_key]
            if os.path.exists(cached):
                print(f"[resolver] ELF cache hit: {build_hash}")
                return cached
            del _elf_cache[cache_key]   # stale entry

    # Download fresh (outside lock — can be slow)
    elf_path = _download_elf_raw(org_id, group_id, firmware_version, build_hash)

    if elf_path:
        with _elf_cache_lock:
            # Evict oldest if cache is full
            if len(_elf_cache) >= _ELF_CACHE_MAX:
                oldest_key = next(iter(_elf_cache))
                try:
                    os.unlink(_elf_cache[oldest_key])
                except Exception:
                    pass
                del _elf_cache[oldest_key]
            _elf_cache[cache_key] = elf_path
            print(f"[resolver] ELF cached: {build_hash} ({len(_elf_cache)}/{_ELF_CACHE_MAX} slots used)")

    return elf_path

# ── Native low-memory symbolization ─────────────────────────────

def resolve_address(elf_path: str, addr: int) -> dict:
    """Resolve PC with GNU binutils rather than loading DWARF into Python RAM.

    addr2line performs the same lookup in a bounded subprocess. Never invoke
    a shell or allow untrusted values to supply command-line options.
    """
    if not isinstance(addr, int) or not 0 <= addr <= 0xFFFFFFFF:
        raise ValueError("Invalid 32-bit instruction address")

    result = {"address": f"0x{addr:08X}", "function": None, "file": None, "line": None}
    # Cortex-M return addresses can have bit zero set (Thumb mode). Do NOT
    # strip bits 30/31 of normal ESP32 PCs; these are valid flash addresses.
    lookup = addr & ~1
    proc = subprocess.run(
        ["addr2line", "-f", "-C", "-e", elf_path, f"0x{lookup:08x}"],
        capture_output=True, text=True, timeout=20, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"addr2line failed (exit {proc.returncode}): {proc.stderr[:160]}")
    lines = proc.stdout.splitlines()
    if len(lines) < 2:
        raise RuntimeError("addr2line did not return function and location")
    function = lines[0].strip()
    location = lines[1].strip()
    if function and function != "??":
        result["function"] = function
    if location and location not in ("??:0", "??:?") and ":" in location:
        source, line = location.rsplit(":", 1)
        if line.isdigit() and int(line) > 0:
            # DWARF paths can contain Windows drive letters/backslashes.
            result["file"] = source.replace(chr(92), "/").rsplit("/", 1)[-1]
            result["line"] = int(line)
    return result

# ── Stack analysis ────────────────────────────────────────────────────────────

def analyse_stack(stack_hex: str, platform: str) -> dict:
    """Extract flash addresses and ASCII strings from raw stack dump."""
    if platform == 'esp32':
        flash_lo, flash_hi = 0x400C0000, 0x40280000
    else:
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

    elf_path = download_elf(req.org_id, req.group_id, req.firmware_version, req.build_hash)
    if not elf_path:
        print(f"[resolver] No ELF found for build_hash={req.build_hash}")
        return ResolveResponse(resolved=False, reason='ELF not found for this build_hash')

    try:
        # Resolve PC
        pc_resolved = resolve_address(elf_path, int(req.pc, 16))
        print(f"[resolver] PC {req.pc} → {pc_resolved['function'] or '?'} "
              f"at {pc_resolved['file'] or '?'}:{pc_resolved['line'] or '?'}")

        # Resolve LR
        lr_resolved = None
        if req.lr:
            try:
                lr_resolved = resolve_address(elf_path, int(req.lr, 16))
                print(f"[resolver] LR {req.lr} → {lr_resolved['function'] or '?'} "
                      f"at {lr_resolved['file'] or '?'}:{lr_resolved['line'] or '?'}")
            except Exception as e:
                print(f"[resolver] LR resolve failed: {e}")

        # Stack analysis
        call_chain, stack_strings = [], []
        if req.stack_data:
            analysis      = analyse_stack(req.stack_data, req.platform)
            stack_strings = analysis['strings']
            for entry in analysis['flash_addresses'][:8]:
                resolved = resolve_address(elf_path, entry['value'])
                if resolved['function']:
                    call_chain.append({**resolved, 'stack_offset': entry['offset']})

        return ResolveResponse(
            resolved=bool(pc_resolved and pc_resolved.get('function')),
            reason=None if pc_resolved and pc_resolved.get('function') else 'PC address is not symbolized by this ELF',
            pc=ResolvedSymbol(**pc_resolved) if pc_resolved else None,
            lr=ResolvedSymbol(**lr_resolved) if lr_resolved else None,
            call_chain=call_chain,
            stack_strings=stack_strings,
        )

    except Exception as e:
        print(f"[resolver] Resolution failed: {e}")
        return ResolveResponse(resolved=False, reason=str(e))

    finally:
        pass  # ELF is kept in cache for subsequent requests