import idaapi
import ida_nalt
import ida_bytes
import ida_segment
import ida_name
import ida_funcs
import idc
import ida_typeinf

til = ida_typeinf.get_idati()

TYPE = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP

Elf32_Rel = "struct Elf32_Rel { unsigned __int32 r_offset; unsigned __int32 r_info; };"

ida_typeinf.parse_decls(til, Elf32_Rel, False, 0)

header = "struct header {   int PT_DYNAMIC_OFF __offset(OFF32,0x38);   int PT_DYNAMIC_COUNT;   int REL_OFF __offset(OFF32,0x38);   int REL_COUNT;   int JMPREL_OFF __offset(OFF32,0x38);   int JMPREL_COUNT;   int SYMTAB_OFF __offset(OFF32,0x38);   int SYMTAB_COUNT;   int STRTAB_OFF __offset(OFF32,0x38);   int STRTAB_COUNT;   int SEGMENT_OFF __offset(OFF32,0x38);   int SEGMENT_COUNT;   int MACHINE_TYPE;   int gap34; };"

ida_typeinf.parse_decls(til, header, False, 0)

_DYN = "union Elf32_Dyn::$A263394DDF3EC2D4B1B8448EDD30E249{  unsigned __int32 d_val;  unsigned __int32 d_ptr;};"

ida_typeinf.parse_decls(til, _DYN, False, 0)

Elf_DTs = "enum Elf_DTs {   DT_NULL = 0x0,   DT_NEEDED = 0x1,   DT_PLTRELSZ = 0x2,   DT_PLTGOT = 0x3,   DT_HASH = 0x4,   DT_STRTAB = 0x5,   DT_SYMTAB = 0x6,   DT_RELA = 0x7,   DT_RELASZ = 0x8,   DT_RELAENT = 0x9,   DT_STRSZ = 0xA,   DT_SYMENT = 0xB,   DT_INIT = 0xC,   DT_FINI = 0xD,   DT_SONAME = 0xE,   DT_RPATH = 0xF,   DT_SYMBOLIC = 0x10,   DT_REL = 0x11,   DT_RELSZ = 0x12,   DT_RELENT = 0x13,   DT_PTRREL = 0x14,   DT_DEBUG = 0x15,   DT_TEXTREL = 0x16,   DT_JMPREL = 0x17,   DT_BIND_NOW = 0x18,   DT_INIT_ARRAY = 0x19,   DT_FINI_ARRAY = 0x1A,   DT_INIT_ARRAYSZ = 0x1B,   DT_FINI_ARRAYSZ = 0x1C,   DT_RUNPATH = 0x1D,   DT_FLAGS = 0x1E,   DT_ENCODING = 0x20,   DT_PREINIT_ARRAY = 0x20,   DT_PREINIT_ARRAYSZ = 0x21,   DT_NUM = 0x22,   OLD_DT_LOOS = 0x60000000,   DT_LOOS = 0x6000000D,   DT_HIOS = 0x6FFFF000,   DT_VALRNGLO = 0x6FFFFD00,   DT_VALRNGHI0 = 0x6FFFFDFF,   DT_ADDRRNGLO = 0x6FFFFE00,   DT_GNU_HASH = 0x6FFFFEF5,   DT_ADDRRNGHI = 0x6FFFFEFF,   DT_VERSYM = 0x6FFFFFF0,   DT_RELACOUNT = 0x6FFFFFF9,   DT_RELCOUNT = 0x6FFFFFFA,   DT_FLAGS_1 = 0x6FFFFFFB,   DT_VERDEF = 0x6FFFFFFC,   DT_VERDEFNUM = 0x6FFFFFFD,   DT_VERNEED = 0x6FFFFFFE,   DT_VERNEEDNUM = 0x6FFFFFFF,   OLD_DT_HIOS = 0x6FFFFFFF,   DT_LOPROC = 0x70000000,   DT_HIPROC = 0x7FFFFFFF, };"

ida_typeinf.parse_decls(til, Elf_DTs, False, 0)

PROT = "enum PROT { PROT_READ = 0x1, PROT_WRITE = 0x2, PROT_EXEC = 0x4, PROT_NONE = 0x0, PROT_GROWSDOWN = 0x1000000, PROT_GROWSUP = 0x2000000, PROT_EXEC_READ = PROT_EXEC | PROT_READ, PROT_EXEC_WRITE = PROT_EXEC | PROT_WRITE,};"

ida_typeinf.parse_decls(til, PROT, False, 0)

SEG = "struct Seg{  int vaddr_or_offset;  int size;  PROT prot_or_type;  int extra;};"

ida_typeinf.parse_decls(til, SEG, False, 0)

Elf32_Dyn = "struct Elf32_Dyn {   Elf_DTs d_tag;   union Elf32_Dyn::$A263394DDF3EC2D4B1B8448EDD30E249 d_un; };"

ida_typeinf.parse_decls(til, Elf32_Dyn, False, 0)

sym_info = "enum __bitmask sym_info : __int8 {   MM_F0h_sym_info_bind_e = 0xF0,        ///< MASK   STB_LOCAL = 0x0,   STB_GLOBAL = 0x10,   STB_WEAK = 0x20,   STB_NUM = 0x30,   STB_LOOS = 0xA0,   STB_GNU_UNIQUE = 0xA0,   STB_HIOS = 0xC0,   STB_LOPROC = 0xD0,   STB_HIPROC = 0xE0,   STB_UNKNOWN = 0xF0,   MM_Fh_sym_info_type_e = 0xF,          ///< MASK   STT_NOTYPE = 0x0,   STT_OBJECT = 0x1,   STT_FUNC = 0x2,   STT_SECTION = 0x3,   STT_FILE = 0x4,   STT_COMMON = 0x5,   STT_TLS = 0x6,   STT_NUM = 0x7,   STT_LOOS = 0xA,   STT_GNU_IFUNC = 0xA,   STT_HIOS = 0xB,   STT_LOPROC = 0xC,   STT_HIPROC = 0xD, };"

ida_typeinf.parse_decls(til, sym_info, False, 0)

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
    
def define_strings(start, size):
    ea = start
    end = start + size

    while ea < end:
        if ida_bytes.get_byte(ea) == 0:
            ea += 1
            continue

        s = read_cstr(ea)
        if len(s) >= 3:
            ida_bytes.create_strlit(ea, len(s) + 1, ida_nalt.STRTYPE_C)
        ea += len(s) + 1
        
def force_code(start, size):
    ea = start
    end = start + size

    while ea < end:
        if idc.create_insn(ea):
            ea = idc.next_head(ea, end)
        else:
            ea += 2  # Thumb-safe step
        
def try_make_entry(addr):
    if ida_bytes.is_loaded(addr):
        ida_funcs.add_func(addr)
        idc.create_insn(addr)
        idaapi.auto_wait()

def is_valid_ptr(ea):
    return ea != 0 and ida_bytes.is_loaded(ea)

def apply_pointer(reloc_addr, val):
    if not is_valid_ptr(reloc_addr):
        print(f"[!] Skipping bad reloc FROM {reloc_addr:08X}")
        return
        
    if not is_valid_ptr(val):
        print(f"[!] Skipping bad reloc TO {val:08X}")
        return
        
    if not ida_bytes.is_loaded(reloc_addr):
        return

    if not ida_bytes.is_loaded(val):
        print(f"[!] Skipping invalid target {val:08X}")
        return

    ida_bytes.patch_dword(reloc_addr, val)

    ida_bytes.del_items(reloc_addr, ida_bytes.DELIT_SIMPLE, 4)
    ida_bytes.create_data(reloc_addr, ida_bytes.FF_DWORD, 4, idaapi.BADADDR)

    idc.op_plain_offset(reloc_addr, 0, 0)

    idaapi.add_dref(reloc_addr, val, idaapi.dr_O)
    
# --------------------------------------------------
# Helpers
# --------------------------------------------------

def in_segment(ea):
    seg = idaapi.getseg(ea)
    return seg is not None and seg.start_ea <= ea < seg.end_ea

def fix_thumb(addr):
    if addr & 1:
        real = addr & ~1
        idc.split_sreg_range(real, "T", 1, idaapi.SR_user)
        return real
    return addr

def read_cstr(ea):
    s = []
    while True:
        c = ida_bytes.get_byte(ea)
        if c == 0:
            break
        s.append(chr(c))
        ea += 1
    return "".join(s)
    
def is_end_of_image(addr):
    seg = idaapi.getseg(addr)
    if not seg:
        return True

    return addr == seg.end_ea

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
    
def apply_rel(rel_base, count, label):
    print(f"[+] Applying {label} @ {rel_base:08X}")

    for i in range(count):
        ea = rel_base + i * 8

        r_offset = u32(ea + 0x0)
        r_info   = u32(ea + 0x4)

        r_type = r_info & 0xFF
        r_sym  = r_info >> 8

        reloc_addr = BASE + r_offset

        if not ida_bytes.is_loaded(reloc_addr):
            continue

        sym = get_sym(r_sym)
        orig = ida_bytes.get_dword(reloc_addr)

        val = None

        if r_type == R_ARM_RELATIVE:
            val = BASE + orig

        elif r_type == R_ARM_ABS32:
            if sym:
                val = BASE + sym["value"] + orig

        elif r_type in (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT):
            if sym:
                val = BASE + sym["value"]

        if val is None:
            continue
        
        if val == 0:
            continue
            
        if not in_segment(reloc_addr):
            continue

        if not in_segment(val):
            continue
            
        if is_end_of_image(val):
            continue
            
        seg = idaapi.getseg(reloc_addr)
        if not seg or reloc_addr + 4 > seg.end_ea:
            print(f"[!] Reloc crosses segment boundary @ {reloc_addr:08X}")
            continue
            
        if sym and sym["value"] == 0:
            # unresolved import or placeholder
            continue
        
        if not ida_bytes.is_loaded(val):
            print(f"[!] BAD target {val:08X} from {reloc_addr:08X}")
            continue

        apply_pointer(reloc_addr, val)

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

Elf32_Sym = f"struct Elf32_Sym {{ unsigned __int32 st_name __offset(OFF32,{str_ea}); unsigned __int32 st_value __off; unsigned __int32 st_size; sym_info st_info; unsigned __int8 st_other; unsigned __int16 st_shndx;}};"

ida_typeinf.parse_decls(til, Elf32_Sym, False, 0)

if STRTAB_COUNT:
    name_region(str_ea, STRTAB_SIZE, ".dynstr")
    define_strings(str_ea, STRTAB_SIZE)

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

for i in range(SEG_TABLE_COUNT):
    ea = seg_base + (i * 0x10)

    vaddr = u32(ea + 0x00)
    size  = u32(ea + 0x04)
    flags = u32(ea + 0x08)
    extra = u32(ea + 0x0C)

    segments.append((vaddr, size, flags, extra))

    print(f"  seg[{i}] vaddr={vaddr:08X} size={size:08X} flags={flags:08X}")

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
    
    if perm & ida_segment.SEGPERM_EXEC:
        force_code(vaddr, size)

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
        
    addr = st_value
    
    if is_end_of_image(addr):
        continue

    addr = fix_thumb(addr)

    if addr > BASE + HDR_SIZE:   # avoid header region
        ida_name.set_name(addr, name, ida_name.SN_FORCE | ida_name.SN_NOWARN)

    # mark as function if plausible
    if st_size > 0:
        ida_funcs.add_func(addr)
        idc.create_insn(addr)
        idaapi.auto_wait()
     
    if st_name != 0:
        str_addr = str_ea + st_name
        idaapi.add_dref(addr, str_addr, idaapi.dr_O)
        
    try_make_entry(addr)

    print(f"  sym[{i}] {name} @ {addr:08X}")

print("[+] Done")