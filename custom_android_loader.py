import idaapi
import ida_bytes
import ida_segment
import ida_name
import ida_funcs

BASE = 0x0
HDR_SIZE = 0x38

R_ARM_NONE       = 0
R_ARM_ABS32      = 2
R_ARM_RELATIVE   = 23
R_ARM_GLOB_DAT   = 21
R_ARM_JUMP_SLOT  = 22

def u32(ea):
    return ida_bytes.get_dword(ea)

def off(x):
    return BASE + HDR_SIZE + x
   
def is_valid_range(ea, size):
    if ea == 0 or size == 0:
        return False
    seg = ida_segment.getseg(ea)
    return seg is not None and ida_segment.getseg(ea + size - 1) is not None
 
def name_region(start, size, name, segclass="DATA"):
    if start == 0 or size == 0:
        return

    if not ida_bytes.is_loaded(start):
        print(f"[!] {name} not in mapped memory")
        return

    end = start + size

    ida_segment.add_segm(0, start, end, name, segclass)

    print(f"[+] Named {name} @ {start:08X} - {end:08X}")

# --------------------------------------------------
# Parse string table helper
# --------------------------------------------------

def read_cstr(ea):
    s = []
    while True:
        c = ida_bytes.get_byte(ea)
        if c == 0:
            break
        s.append(chr(c))
        ea += 1
    return "".join(s)

    
def apply_rel(rel_base, count, label):
    print(f"[+] Applying {label} REL @ {rel_base:08X} count={count}")

    for i in range(count):
        ea = rel_base + (i * 8)

        if not ida_bytes.is_loaded(ea):
            continue

        r_offset = u32(ea + 0x00)
        r_info   = u32(ea + 0x04)

        r_type = r_info & 0xFF
        r_sym  = r_info >> 8

        if not ida_bytes.is_loaded(r_offset):
            continue

        sym = get_sym(r_sym)

        # Current value at relocation target
        orig = ida_bytes.get_dword(r_offset)

        # ---- HANDLE TYPES ----

        if r_type == R_ARM_RELATIVE:
            # B + A
            val = BASE + orig
            #ida_bytes.patch_dword(r_offset, val)

        elif r_type == R_ARM_ABS32:
            if sym:
                val = sym["value"] + orig
                #ida_bytes.patch_dword(r_offset, val)

                if sym["name"]:
                    ida_name.set_name(val, sym["name"], ida_name.SN_NOWARN)

        elif r_type in (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT):
            if sym:
                val = sym["value"]
                #ida_bytes.patch_dword(r_offset, val)

                if sym["name"]:
                    ida_name.set_name(r_offset, f"{sym['name']}_ptr", ida_name.SN_NOWARN)

        else:
            print(f"    [!] Unhandled REL type {r_type} @ {ea:08X}")

# --------------------------------------------------
# Parse main header
# --------------------------------------------------

hdr = BASE

PT_DYNAMIC_OFF   = u32(hdr + 0x00) # .dynamic
PT_DYNAMIC_COUNT = u32(hdr + 0x04)
DYNAMIC_SIZE     = PT_DYNAMIC_COUNT * 8

REL_OFF          = u32(hdr + 0x08) # .rel.dyn
REL_COUNT        = u32(hdr + 0x0C) 
REL_SIZE         = REL_COUNT * 8

JMPREL_OFF       = u32(hdr + 0x10) # .rel.plt
JMPREL_COUNT     = u32(hdr + 0x14)
JMPREL_SIZE      = JMPREL_COUNT * 8

SYMTAB_OFF       = u32(hdr + 0x18) # .dynsym
SYMTAB_COUNT     = u32(hdr + 0x1C)
SYMTAB_SIZE      = SYMTAB_COUNT * 0x10

STRTAB_OFF       = u32(hdr + 0x20) # .dynstr
STRTAB_COUNT     = u32(hdr + 0x24)
STRTAB_SIZE      = STRTAB_COUNT

print("[+] Header parsed")

dyn_ea   = off(PT_DYNAMIC_OFF)

if PT_DYNAMIC_COUNT:
    name_region(dyn_ea, DYNAMIC_SIZE, ".dynamic")

sym_ea   = off(SYMTAB_OFF)

if SYMTAB_COUNT:
    name_region(sym_ea, SYMTAB_SIZE, ".dynsym")

str_ea   = off(STRTAB_OFF)

if STRTAB_COUNT:
    name_region(str_ea, STRTAB_SIZE, ".dynstr")

if REL_OFF != 0 and REL_COUNT != 0:
    rel_ea = off(REL_OFF)
    if is_valid_range(rel_ea, REL_COUNT * 8):
        apply_rel(rel_ea, REL_COUNT, ".rel.dyn")
    else:
        print("[!] REL table invalid range")
else:
    print("[*] No REL table")
    
if REL_OFF and REL_COUNT:
    name_region(rel_ea, REL_SIZE, ".rel.dyn")
    
if JMPREL_OFF != 0 and JMPREL_COUNT != 0:
    jmp_ea = off(JMPREL_OFF)
    if is_valid_range(jmp_ea, JMPREL_COUNT * 8):
        apply_rel(jmp_ea, JMPREL_COUNT, ".rel.plt")
    else:
        print("[!] JMPREL table invalid range")
else:
    print("[*] No JMPREL table")
    
if JMPREL_OFF and JMPREL_COUNT:
    name_region(jmp_ea, JMPREL_SIZE, ".rel.plt")

# --------------------------------------------------
# Segment table (custom)
# --------------------------------------------------

SEG_TABLE_OFF   = u32(hdr + 0x28)
SEG_TABLE_COUNT = u32(hdr + 0x2C)
SEG_TABLE_UNK   = u32(hdr + 0x30)

seg_base = off(SEG_TABLE_OFF)

print(f"[+] Segment table @ {seg_base:08X}, count={SEG_TABLE_COUNT}")

segments = []

# for i in range(SEG_TABLE_COUNT):
#     ea = seg_base + (i * 0x10)
# 
#     vaddr = u32(ea + 0x00)
#     size  = u32(ea + 0x04)
#     flags = u32(ea + 0x08)
#     extra = u32(ea + 0x0C)
# 
#     segments.append((vaddr, size, flags, extra))
# 
#     print(f"  seg[{i}] vaddr={vaddr:08X} size={size:08X} flags={flags:08X}")

# --------------------------------------------------
# Create segments in IDA
# --------------------------------------------------

def make_seg(start, size, name, perm):
    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea   = start + size
    seg.bitness  = 1  # 32-bit

    # Set permissions BEFORE adding
    seg.perm = perm

    ida_segment.add_segm_ex(seg, name, "CODE", ida_segment.ADDSEG_OR_DIE)

for i, (vaddr, size, flags, _) in enumerate(segments):

    # heuristic flag mapping
    perm = 0
    if flags & 1: perm |= ida_segment.SEGPERM_EXEC
    if flags & 2: perm |= ida_segment.SEGPERM_WRITE
    if flags & 4: perm |= ida_segment.SEGPERM_READ

    if perm == 0:
        perm = ida_segment.SEGPERM_READ

    make_seg(vaddr, size, f"seg_{i}", perm)

# --------------------------------------------------
# Parse symbols
# --------------------------------------------------

print("[+] Parsing symbols")

for i in range(SYMTAB_COUNT):
    ea = sym_ea + (i * 0x10)

    st_name  = u32(ea + 0x00)
    st_value = u32(ea + 0x04)
    st_size  = u32(ea + 0x08)
    st_info  = ida_bytes.get_byte(ea + 0x0C)
    st_other = ida_bytes.get_byte(ea + 0x0D)
    st_shndx = ida_bytes.get_word(ea + 0x0E)

    if st_name == 0:
        continue

    name = read_cstr(str_ea + st_name)

    if not name:
        continue

    ida_name.set_name(st_value, name, ida_name.SN_FORCE | ida_name.SN_NOWARN)

    # mark as function if plausible
    if st_size > 0:
        ida_funcs.add_func(st_value)

    print(f"  sym[{i}] {name} @ {st_value:08X}")

def get_sym(sym_index):
    if sym_index >= SYMTAB_COUNT:
        return None

    ea = sym_ea + (sym_index * 0x10)

    st_name  = u32(ea + 0x00)
    st_value = u32(ea + 0x04)

    name = ""
    if st_name != 0:
        name = read_cstr(str_ea + st_name)

    return {
        "value": st_value,
        "name": name
    }

print("[+] Done")