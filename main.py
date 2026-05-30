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
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from elftools.elf.elffile import ELFFile
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
    if RESOLVER_SECRET and x_resolver_secret != RESOLVER_SECRET:
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
_elf_cache: dict = {}          # build_hash → temp file path
_elf_cache_lock = threading.Lock()
_ELF_CACHE_MAX = 3             # keep at most 3 ELFs in memory

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

    # Org-wide search
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


def download_elf(org_id: str, group_id: Optional[str],
                 firmware_version: str, build_hash: str) -> Optional[str]:
    """Return cached ELF path or download fresh. Cache survives between requests."""
    with _elf_cache_lock:
        if build_hash in _elf_cache:
            cached = _elf_cache[build_hash]
            if os.path.exists(cached):
                print(f"[resolver] ELF cache hit: {build_hash}")
                return cached
            del _elf_cache[build_hash]   # stale entry

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
            _elf_cache[build_hash] = elf_path
            print(f"[resolver] ELF cached: {build_hash} ({len(_elf_cache)}/{_ELF_CACHE_MAX} slots used)")

    return elf_path

# ── Core DWARF resolver with inline frame walking ─────────────────────────────

def resolve_address(elf_path: str, addr: int) -> dict:
    """
    Resolve address → function/file/line using DWARF.

    Algorithm:
    1. Symbol table (.symtab) → function name (most reliable for ESP32)
    2. DWARF .debug_info → walk DW_TAG_inlined_subroutine to find the
       outermost non-stdlib application frame (gives correct file/line)
    3. DWARF .debug_line → file/line fallback if inline walk fails
    4. Filter stdlib inlined frames (svfiprintf etc.)
    """
    result = {'address': f'0x{addr:08X}', 'function': None, 'file': None, 'line': None}

    # Address variants to try
    clean   = addr & ~1           # strip ARM Thumb bit
    xtensa  = addr & 0x3FFFFFFF   # strip Xtensa CALL8 top 2 bits

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)

        # ── Step 1: Symbol table → function name ─────────────────────────────
        symtab = elf.get_section_by_name('.symtab')
        if symtab:
            best_fn, best_offset = None, float('inf')
            for sym in symtab.iter_symbols():
                if sym['st_info']['type'] not in ('STT_FUNC', 'STT_NOTYPE'):
                    continue
                # Filter ARM mapping symbols ($t=Thumb, $d=data, $a=ARM, $x=mixed)
                if sym.name in ('$t', '$d', '$a', '$x'):
                    continue
                saddr = sym['st_value'] & ~1   # strip Thumb bit from symbol
                ssize = sym['st_size']
                for a in (clean, xtensa):
                    if saddr <= a < saddr + max(ssize, 1):
                        offset = a - saddr
                        if offset < best_offset:
                            best_offset = offset
                            best_fn = sym.name
            if best_fn:
                result['function'] = best_fn

        if not elf.has_dwarf_info():
            return result

        dwarf = elf.get_dwarf_info()

        # ── Step 2: Inline frame walking via DW_TAG_inlined_subroutine ────────
        #
        # When the compiler inlines a function (e.g. snprintf into app_main),
        # DWARF records this as a DW_TAG_inlined_subroutine child DIE inside
        # the parent DW_TAG_subprogram. The call site attributes
        # DW_AT_call_file and DW_AT_call_line give us the exact source line
        # in the OUTER (application) code where the inlined call originated.
        #
        # Strategy: for our address, find the deepest inline frame that is
        # NOT a stdlib function. That gives us the real application file/line.

        def get_die_name(die) -> Optional[str]:
            name_attr = die.attributes.get('DW_AT_name')
            if name_attr:
                v = name_attr.value
                return v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)
            # Try DW_AT_abstract_origin / DW_AT_specification for name
            for ref_attr in ('DW_AT_abstract_origin', 'DW_AT_specification'):
                ref = die.attributes.get(ref_attr)
                if ref:
                    try:
                        ref_die = die.cu.get_DIE_from_refaddr(ref.value + die.cu.cu_offset)
                        n = ref_die.attributes.get('DW_AT_name')
                        if n:
                            v = n.value
                            return v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)
                    except Exception:
                        pass
            return None

        def die_contains_addr(die) -> bool:
            low = die.attributes.get('DW_AT_low_pc')
            high = die.attributes.get('DW_AT_high_pc')
            if not (low and high):
                return False
            lo = low.value
            hi = high.value if high.form == 'DW_FORM_addr' else lo + high.value
            for a in (clean, xtensa):
                if lo <= a < hi:
                    return True
            return False

        def get_file_name(cu, file_idx: int) -> Optional[str]:
            """Get filename from DWARF line program file table."""
            try:
                lp = dwarf.line_program_for_CU(cu)
                if lp is None:
                    return None
                entries = lp.header.get('file_entry', [])
                if 0 < file_idx <= len(entries):
                    fe = entries[file_idx - 1]
                    name = fe.name
                    fname = name.decode('utf-8', errors='replace') if isinstance(name, bytes) else str(name)
                    return fname.split('/')[-1]  # basename only
            except Exception:
                pass
            return None

        def is_stdlib(name: Optional[str]) -> bool:
            if not name:
                return False
            return any(p in name.lower() for p in STDLIB_PATTERNS)

        # Walk all CUs looking for inlined frames at our address
        best_app_frame = None  # (file, line) of outermost non-stdlib frame

        for CU in dwarf.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag != 'DW_TAG_subprogram':
                    continue
                if not die_contains_addr(DIE):
                    continue

                # This subprogram contains our address — walk its children
                # for inlined subroutines
                for child in DIE.iter_children():
                    if child.tag != 'DW_TAG_inlined_subroutine':
                        continue
                    if not die_contains_addr(child):
                        continue

                    # This inlined call contains our address
                    # DW_AT_call_file + DW_AT_call_line = where it was called FROM
                    # (the application source line we want)
                    call_file_attr = child.attributes.get('DW_AT_call_file')
                    call_line_attr = child.attributes.get('DW_AT_call_line')

                    if call_file_attr and call_line_attr:
                        fname       = get_file_name(CU, call_file_attr.value)
                        line        = call_line_attr.value
                        inline_name = get_die_name(child)

                        # Only accept application code — skip stdlib and IDF internals
                        # Keep updating best_app_frame so we end up with the
                        # OUTERMOST non-stdlib frame (the real application call site)
                        if not is_stdlib(fname) and not is_stdlib(inline_name):
                            best_app_frame = (fname, line)

        if best_app_frame:
            result['file'], result['line'] = best_app_frame
            print(f"[resolver] Inline walk: {result['function']} at "
                  f"{result['file']}:{result['line']}")
            return result

        # ── Step 3: DWARF .debug_line — exact addr2line algorithm ───────────
        #
        # addr2line scans the line table sequentially using prev/curr pairs.
        # When prev.address <= target < curr.address, prev is the answer.
        # We collect ALL such matches across all CUs (multiple files can match)
        # then pick the best application file.
        all_line_matches = []  # list of (basename, line, addr)

        for CU in dwarf.iter_CUs():
            try:
                li = dwarf.line_program_for_CU(CU)
                if li is None:
                    continue
                lp = li.header
                prev = None
                for entry in li.get_entries():
                    if entry.state is None:
                        continue
                    state = entry.state
                    if prev is not None:
                        # Check if target falls in [prev.address, state.address)
                        for a in (clean, xtensa):
                            if prev.address <= a < state.address:
                                try:
                                    fi = lp.file_entry[prev.file - 1]
                                    fname = fi.name.decode('utf-8', errors='replace')
                                    if fi.dir_index > 0:
                                        d = lp.include_directory[fi.dir_index - 1]
                                        dname = d.decode('utf-8', errors='replace')
                                        fname = dname + '/' + fname
                                    basename = fname.split('/')[-1]
                                    all_line_matches.append((basename, prev.line, prev.address))
                                except Exception:
                                    pass
                                break
                    prev = state
            except Exception:
                continue

        # Sort by address descending — highest addr (closest to target) first
        all_line_matches.sort(key=lambda x: x[2], reverse=True)

        # Pick best match — prefer application files over IDF/stdlib
        # Application files: short names ending in .c/.h, not in known IDF dirs
        def is_app_file(fname: str) -> bool:
            if not fname or not fname.endswith(('.c', '.h')):
                return False
            if is_stdlib(fname):
                return False
            # Reject IDF component paths
            idf_dirs = [
                'components/', 'esp-idf/', '/idf/', 'esp_idf',
                'esp32', 'xtensa', 'riscv', 'soc/', 'hal/',
                'lwip', 'mbedtls', 'nvs', 'driver/',
                'efuse', 'wpa', 'ieee802', 'coex',
                'ubsan', 'sanitizer', 'compiler-rt', 'gcc',
                'libgcc', 'crtbegin', 'crtstuff',
                # STM32 HAL internals
                'stm32l4xx_it', 'stm32l4xx_hal', 'system_stm32',
                'cmsis', 'freertos', 'syscalls', 'sysmem',
            ]
            fname_lower = fname.lower()
            return not any(d in fname_lower for d in idf_dirs)

        # First pass: prefer application files (main.c, sensor.c etc)
        for fname, line, _ in all_line_matches:
            if is_app_file(fname):
                result['file'] = fname
                result['line'] = line
                print(f"[resolver] debug_line (app): {result['function']} at {fname}:{line}")
                break

        # Second pass: any non-stdlib match
        if not result['file']:
            for fname, line, _ in all_line_matches:
                if not is_stdlib(fname):
                    result['file'] = fname
                    result['line'] = line
                    print(f"[resolver] debug_line (fallback): {result['function']} at {fname}:{line}")
                    break
        # If still nothing — function name alone is useful enough

        # ── Step 5: DWARF .debug_info fallback for function name ──────────────
        if result['function'] is None:
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
                        for a in (clean, xtensa):
                            if lo <= a < hi:
                                result['function'] = name.value.decode('utf-8', errors='replace')
                                break
                    except Exception:
                        continue
                if result['function']:
                    break

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
        pass  # ELF is kept in cache for subsequent requests