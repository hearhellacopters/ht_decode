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

r_info = "enum r_info : __int32{  R_AARCH64_NONE = 0x100,  R_AARCH64_ABS64 = 0x101,  R_AARCH64_ABS32 = 0x102,  R_AARCH64_ABS16 = 0x103,  R_AARCH64_PREL64 = 0x104,  R_AARCH64_PREL32 = 0x105,  R_AARCH64_PREL16 = 0x106,  R_AARCH64_MOVW_UABS_G0 = 0x107,  R_AARCH64_MOVW_UABS_G0_NC = 0x108,  R_AARCH64_MOVW_UABS_G1 = 0x109,  R_AARCH64_MOVW_UABS_G1_NC = 0x10A,  R_AARCH64_MOVW_UABS_G2 = 0x10B,  R_AARCH64_MOVW_UABS_G2_NC = 0x10C,  R_AARCH64_MOVW_UABS_G3 = 0x10D,  R_AARCH64_MOVW_SABS_G0 = 0x10E,  R_AARCH64_MOVW_SABS_G1 = 0x10F,  R_AARCH64_MOVW_SABS_G2 = 0x110,  R_AARCH64_LD_PREL_LO19 = 0x111,  R_AARCH64_ADR_PREL_LO21 = 0x112,  R_AARCH64_ADR_PREL_PG_HI21 = 0x113,  R_AARCH64_ADR_PREL_PG_HI21_NC = 0x114,  R_AARCH64_ADD_ABS_LO12_NC = 0x115,  R_AARCH64_LDST8_ABS_LO12_NC = 0x116,  R_AARCH64_TSTBR14 = 0x117,  R_AARCH64_CONDBR19 = 0x118,  R_AARCH64_JUMP26 = 0x11A,  R_AARCH64_CALL26 = 0x11B,  R_AARCH64_LDST16_ABS_LO12_NC = 0x11C,  R_AARCH64_LDST32_ABS_LO12_NC = 0x11D,  R_AARCH64_LDST64_ABS_LO12_NC = 0x11E,  R_AARCH64_MOVW_PREL_G0 = 0x11F,  R_AARCH64_MOVW_PREL_G0_NC = 0x120,  R_AARCH64_MOVW_PREL_G1 = 0x121,  R_AARCH64_MOVW_PREL_G1_NC = 0x122,  R_AARCH64_MOVW_PREL_G2 = 0x123,  R_AARCH64_MOVW_PREL_G2_NC = 0x124,  R_AARCH64_MOVW_PREL_G3 = 0x125,  R_AARCH64_MOVW_GOTOFF_G0 = 0x12C,  R_AARCH64_MOVW_GOTOFF_G0_NC = 0x12D,  R_AARCH64_MOVW_GOTOFF_G1 = 0x12E,  R_AARCH64_MOVW_GOTOFF_G1_NC = 0x12F,  R_AARCH64_MOVW_GOTOFF_G2 = 0x130,  R_AARCH64_MOVW_GOTOFF_G2_NC = 0x131,  R_AARCH64_MOVW_GOTOFF_G3 = 0x132,  R_AARCH64_GOTREL64 = 0x133,  R_AARCH64_GOTREL32 = 0x134,  R_AARCH64_GOT_LD_PREL19 = 0x135,  R_AARCH64_LD64_GOTOFF_LO15 = 0x136,  R_AARCH64_ADR_GOT_PAGE = 0x137,  R_AARCH64_LD64_GOT_LO12_NC = 0x138,  R_AARCH64_TLSGD_ADR_PREL21 = 0x200,  R_AARCH64_TLSGD_ADR_PAGE21 = 0x201,  R_AARCH64_TLSGD_ADD_LO12_NC = 0x202,  R_AARCH64_TLSGD_MOVW_G1 = 0x203,  R_AARCH64_TLSGD_MOVW_G0_NC = 0x204,  R_AARCH64_TLSLD_ADR_PREL21 = 0x205,  R_AARCH64_TLSLD_ADR_PAGE21 = 0x206,  R_AARCH64_TLSLD_ADD_LO12_NC = 0x207,  R_AARCH64_TLSLD_MOVW_G1 = 0x208,  R_AARCH64_TLSLD_MOVW_G0_NC = 0x209,  R_AARCH64_TLSLD_LD_PREL19 = 0x20A,  R_AARCH64_TLSLD_MOVW_DTPREL_G2 = 0x20B,  R_AARCH64_TLSLD_MOVW_DTPREL_G1 = 0x20C,  R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC = 0x20D,  R_AARCH64_TLSLD_MOVW_DTPREL_G0 = 0x20E,  R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC = 0x20F,  R_AARCH64_TLSLD_ADD_DTPREL_HI12 = 0x210,  R_AARCH64_TLSLD_ADD_DTPREL_LO12 = 0x211,  R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC = 0x212,  R_AARCH64_TLSLD_LDST8_DTPREL_LO12 = 0x213,  R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC = 0x214,  R_AARCH64_TLSLD_LDST16_DTPREL_LO12 = 0x215,  R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC = 0x216,  R_AARCH64_TLSLD_LDST32_DTPREL_LO12 = 0x217,  R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC = 0x218,  R_AARCH64_TLSLD_LDST64_DTPREL_LO12 = 0x219,  R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC = 0x21A,  R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 = 0x21B,  R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC = 0x21C,  R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 = 0x21D,  R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC = 0x21E,  R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 = 0x21F,  R_AARCH64_TLSLE_MOVW_TPREL_G2 = 0x220,  R_AARCH64_TLSLE_MOVW_TPREL_G1 = 0x221,  R_AARCH64_TLSLE_MOVW_TPREL_G1_NC = 0x222,  R_AARCH64_TLSLE_MOVW_TPREL_G0 = 0x223,  R_AARCH64_TLSLE_MOVW_TPREL_G0_NC = 0x224,  R_AARCH64_TLSLE_ADD_TPREL_HI12 = 0x225,  R_AARCH64_TLSLE_ADD_TPREL_LO12 = 0x226,  R_AARCH64_TLSLE_ADD_TPREL_LO12_NC = 0x227,  R_AARCH64_TLSLE_LDST8_TPREL_LO12 = 0x228,  R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC = 0x229,  R_AARCH64_TLSLE_LDST16_TPREL_LO12 = 0x22A,  R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC = 0x22B,  R_AARCH64_TLSLE_LDST32_TPREL_LO12 = 0x22C,  R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC = 0x22D,  R_AARCH64_TLSLE_LDST64_TPREL_LO12 = 0x22E,  R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC = 0x22F,  R_AARCH64_COPY = 0x400,  R_AARCH64_GLOB_DAT = 0x401,  R_AARCH64_JUMP_SLOT = 0x402,  R_AARCH64_RELATIVE = 0x403,  R_AARCH64_TLS_DTPREL64 = 0x404,  R_AARCH64_TLS_DTPMOD64 = 0x405,  R_AARCH64_TLS_TPREL64 = 0x406,  R_AARCH64_TLS_DTPREL32 = 0x407,  R_AARCH64_TLS_DTPMOD32 = 0x408,  R_AARCH64_TLS_TPREL32 = 0x409,};"

ida_typeinf.parse_decls(til, r_info, False, 0)

Elf64_Rela = "struct __attribute__((packed)) Elf64_Rela {  unsigned __int64 r_offset __off;  r_info r_info;  unsigned __int32 index __udec; __int64 r_addend __off; };"

ida_typeinf.parse_decls(til, Elf64_Rela, False, 0)

header = "struct header {   int PROHEADDIR_OFF __off;   int PROHEADDIR_COUNT;   int PT_DYNAMIC_OFF __off;   int PT_DYNAMIC_COUNT;   int STRTAB_OFF __off;   int STRTAB_COUNT;   int SYMTAB_OFF __off;   int SYMTAB_COUNT;   int REL_OFF __off;   int REL_COUNT;   int JMPREL_OFF __off;   int JMPREL_COUNT;   int gap30;   int gap34;   int MACHINE_TYPE;    };"

ida_typeinf.parse_decls(til, header, False, 0)

Elf_DTs = "enum Elf_DTs : __int64{  DT_NULL = 0x0LL,  DT_NEEDED = 0x1LL,  DT_PLTRELSZ = 0x2LL,  DT_PLTGOT = 0x3LL,  DT_HASH = 0x4LL,  DT_STRTAB = 0x5LL,  DT_SYMTAB = 0x6LL,  DT_RELA = 0x7LL,  DT_RELASZ = 0x8LL,  DT_RELAENT = 0x9LL,  DT_STRSZ = 0xALL,  DT_SYMENT = 0xBLL,  DT_INIT = 0xCLL,  DT_FINI = 0xDLL,  DT_SONAME = 0xELL,  DT_RPATH = 0xFLL,  DT_SYMBOLIC = 0x10LL,  DT_REL = 0x11LL,  DT_RELSZ = 0x12LL,  DT_RELENT = 0x13LL,  DT_PTRREL = 0x14LL,  DT_DEBUG = 0x15LL,  DT_TEXTREL = 0x16LL,  DT_JMPREL = 0x17LL,  DT_BIND_NOW = 0x18LL,  DT_INIT_ARRAY = 0x19LL,  DT_FINI_ARRAY = 0x1ALL,  DT_INIT_ARRAYSZ = 0x1BLL,  DT_FINI_ARRAYSZ = 0x1CLL,  DT_RUNPATH = 0x1DLL,  DT_FLAGS = 0x1ELL,  DT_ENCODING = 0x20LL,  DT_PREINIT_ARRAY = 0x20LL,  DT_PREINIT_ARRAYSZ = 0x21LL,  DT_NUM = 0x22LL,  OLD_DT_LOOS = 0x60000000LL,  DT_LOOS = 0x6000000DLL,  DT_HIOS = 0x6FFFF000LL,  DT_VALRNGLO = 0x6FFFFD00LL,  DT_VALRNGHI0 = 0x6FFFFDFFLL,  DT_ADDRRNGLO = 0x6FFFFE00LL,  DT_GNU_HASH = 0x6FFFFEF5LL,  DT_ADDRRNGHI = 0x6FFFFEFFLL,  DT_VERSYM = 0x6FFFFFF0LL,  DT_RELACOUNT = 0x6FFFFFF9LL,  DT_RELCOUNT = 0x6FFFFFFALL,  DT_FLAGS_1 = 0x6FFFFFFBLL,  DT_VERDEF = 0x6FFFFFFCLL,  DT_VERDEFNUM = 0x6FFFFFFDLL,  DT_VERNEED = 0x6FFFFFFELL,  DT_VERNEEDNUM = 0x6FFFFFFFLL,  OLD_DT_HIOS = 0x6FFFFFFFLL,  DT_LOPROC = 0x70000000LL,  DT_HIPROC = 0x7FFFFFFFLL,};"

ida_typeinf.parse_decls(til, Elf_DTs, False, 0)

Elf64_Dyn = "struct Elf64_Dyn {  Elf_DTs d_tag;  unsigned __int64 d_un;};"

ida_typeinf.parse_decls(til, Elf64_Dyn, False, 0)

Elf_PTs = "enum Elf_PTs{  PT_NULL = 0x0,  PT_LOAD = 0x1,  PT_DYNAMIC = 0x2,  PT_INTERP = 0x3,  PT_NOTE = 0x4,  PT_SHLIB = 0x5,  PT_PHDR = 0x6,  PT_TLS = 0x7,  PT_NUM = 0x8,  PT_LOOS = 0x60000000,  PT_HIOS = 0x6FFFFFFF,  PT_LOPROC = 0x70000000,  PT_HIPROC = 0x7FFFFFFF,  PT_GNU_EH_FRAME = 0x6474E550,  PT_GNU_STACK = 0x6474E551,  PT_GNU_RELRO = 0x6474E552,  PT_L4_STACK = 0x60000012,  PT_L4_AUX = 0x60000014,};"

ida_typeinf.parse_decls(til, Elf_PTs, False, 0)

p_flags32_e = "enum p_flags32_e : __int32 {  PF_None = 0x0,  PF_Exec = 0x1,  PF_Write = 0x2,  PF_Write_Exec = 0x3,  PF_Read = 0x4,  PF_Read_Exec = 0x5,  PF_Read_Write = 0x6,  PF_Read_Write_Exec = 0x7,};"

ida_typeinf.parse_decls(til, p_flags32_e, False, 0)

Elf64_Phdr = "struct Elf64_Phdr{  Elf_PTs p_type;  p_flags32_e p_flags;  __int64 p_offset;  __int64 p_vaddr;  __int64 p_paddr;  __int64 p_filesz;  __int64 p_memsz;  __int64 p_align;};"

ida_typeinf.parse_decls(til, Elf64_Phdr, False, 0)

PROT = "enum PROT { PROT_READ = 0x1, PROT_WRITE = 0x2, PROT_EXEC = 0x4, PROT_NONE = 0x0, PROT_GROWSDOWN = 0x1000000, PROT_GROWSUP = 0x2000000, PROT_EXEC_READ = PROT_EXEC | PROT_READ, PROT_EXEC_WRITE = PROT_EXEC | PROT_WRITE,};"

ida_typeinf.parse_decls(til, PROT, False, 0)

SEG = "struct Seg{  int vaddr_or_offset;  int size;  PROT prot_or_type;  int extra;};"

ida_typeinf.parse_decls(til, SEG, False, 0)

sym_info = "enum __bitmask sym_info : __int8 {   MM_F0h_sym_info_bind_e = 0xF0,   STB_LOCAL = 0x0,   STB_GLOBAL = 0x10,   STB_WEAK = 0x20,   STB_NUM = 0x30,   STB_LOOS = 0xA0,   STB_GNU_UNIQUE = 0xA0,   STB_HIOS = 0xC0,   STB_LOPROC = 0xD0,   STB_HIPROC = 0xE0,   STB_UNKNOWN = 0xF0,   MM_Fh_sym_info_type_e = 0xF,   STT_NOTYPE = 0x0,   STT_OBJECT = 0x1,   STT_FUNC = 0x2,   STT_SECTION = 0x3,   STT_FILE = 0x4,   STT_COMMON = 0x5,   STT_TLS = 0x6,   STT_NUM = 0x7,   STT_LOOS = 0xA,   STT_GNU_IFUNC = 0xA,   STT_HIOS = 0xB,   STT_LOPROC = 0xC,   STT_HIPROC = 0xD, };"

ida_typeinf.parse_decls(til, sym_info, False, 0)

BASE = 0x0
HDR_SIZE = 0x3C

R_ARM_NONE       = 0
R_ARM_ABS32      = 2
R_ARM_RELATIVE   = 23
R_ARM_GLOB_DAT   = 21
R_ARM_JUMP_SLOT  = 22

def u32(ea):
    return ida_bytes.get_dword(ea)

def u64(ea):
    return ida_bytes.get_qword(ea)

def off(x):
    return BASE + x
   
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

    ea = sym_ea + (sym_index * 0x18)

    st_name  = u32(ea + 0x00)
    st_value = u64(ea + 0x08)

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
        ea = rel_base + i * 24

        r_offset = u64(ea + 0x0)
        r_type   = u32(ea + 0x8)
        r_sym    = u32(ea + 0xC)

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

PROHEADDIR_OFF   = u32(hdr + 0x00)
PROHEADDIR_COUNT = u32(hdr + 0x04)

PT_DYNAMIC_OFF   = u32(hdr + 0x08) # .dynamic
PT_DYNAMIC_COUNT = u32(hdr + 0x0C)
DYNAMIC_SIZE     = PT_DYNAMIC_COUNT * 16

STRTAB_OFF       = u32(hdr + 0x10) # .dynstr
STRTAB_COUNT     = u32(hdr + 0x14)
STRTAB_SIZE      = STRTAB_COUNT

SYMTAB_OFF       = u32(hdr + 0x18) # .dynsym
SYMTAB_COUNT     = u32(hdr + 0x1C)
SYMTAB_SIZE      = SYMTAB_COUNT * 24

REL_OFF          = u32(hdr + 0x20) # .rel.dyn
REL_COUNT        = u32(hdr + 0x24) 
REL_SIZE         = REL_COUNT * 24

JMPREL_OFF       = u32(hdr + 0x28) # .rel.plt
JMPREL_COUNT     = u32(hdr + 0x2C)
JMPREL_SIZE      = JMPREL_COUNT * 24

MACHINE_TYPE    = u32(hdr + 0x38)

print("[+] Header parsed")

dyn_ea   = off(PT_DYNAMIC_OFF)

if PT_DYNAMIC_COUNT:
    name_region(dyn_ea, DYNAMIC_SIZE, ".dynamic")

sym_ea   = off(SYMTAB_OFF)

if SYMTAB_COUNT:
    name_region(sym_ea, SYMTAB_SIZE, ".dynsym")

str_ea   = off(STRTAB_OFF)

Elf64_Sym = f"struct Elf64_Sym {{ unsigned __int32 st_name __offset(OFF64,{str_ea}); sym_info st_info; unsigned __int8 st_other; unsigned __int16 st_shndx;  unsigned __int64 st_value __off; unsigned __int64 st_size;}};"

ida_typeinf.parse_decls(til, Elf64_Sym, False, 0)

if STRTAB_COUNT:
    name_region(str_ea, STRTAB_SIZE, ".dynstr")
    define_strings(str_ea, STRTAB_SIZE)

if REL_OFF != 0 and REL_COUNT != 0:
    rel_ea = off(REL_OFF)
    if is_valid_range(rel_ea, REL_SIZE):
        apply_rel(rel_ea, REL_COUNT, ".rel.dyn")
    else:
        print("[!] REL table invalid range")
else:
    print("[*] No REL table")
    
if REL_OFF and REL_COUNT:
    name_region(rel_ea, REL_SIZE, ".rel.dyn")
    
if JMPREL_OFF != 0 and JMPREL_COUNT != 0:
    jmp_ea = off(JMPREL_OFF)
    if is_valid_range(jmp_ea, JMPREL_SIZE):
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

seg_base = off(PROHEADDIR_OFF)

print(f"[+] Segment table @ {seg_base:08X}, count={PROHEADDIR_COUNT}")

segments = []

for i in range(PROHEADDIR_COUNT):
    ea = seg_base + (i * 0x38)

    flags = u32(ea + 0x04)
    vaddr = u64(ea + 0x10)
    size  = u64(ea + 0x20)
    extra = u64(ea + 0x30)

    if vaddr > BASE + HDR_SIZE:
        segments.append((vaddr, size, flags, extra))

        print(f"  seg[{i}] vaddr={vaddr:08X} size={size:08X} flags={flags:08X}")

# --------------------------------------------------
# Create segments in IDA
# --------------------------------------------------

def make_seg(start, size, name, perm, className):
    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea   = start + size
    seg.bitness  = 2  # -bit

    # Set permissions BEFORE adding
    seg.perm = perm

    ida_segment.add_segm_ex(seg, name, className, ida_segment.ADDSEG_OR_DIE)

for i, (vaddr, size, flags, _) in enumerate(segments):

    # heuristic flag mapping
    perm = 0
    
    className = "DATA"
    
    if flags == 1: 
        perm |= ida_segment.SEGPERM_EXEC
        className = "CODE"
    if flags == 2: 
        perm |= ida_segment.SEGPERM_WRITE
    if flags == 3: 
        perm |= ida_segment.SEGPERM_WRITE
        perm |= ida_segment.SEGPERM_EXEC
        className = "CODE"
    if flags == 4: 
        perm |= ida_segment.SEGPERM_READ
    if flags == 5:  
        perm |= ida_segment.SEGPERM_READ
        perm |= ida_segment.SEGPERM_EXEC
        className = "CODE"
    if flags == 6:
        perm |= ida_segment.SEGPERM_READ
        perm |= ida_segment.SEGPERM_WRITE
    if flags == 7:
        perm |= ida_segment.SEGPERM_WRITE
        perm |= ida_segment.SEGPERM_READ
        perm |= ida_segment.SEGPERM_EXEC
        className = "CODE"

    if perm == 0:
        perm = ida_segment.SEGPERM_READ

    make_seg(vaddr, size, f"{className}_{i}", perm, className)
    
    if perm & ida_segment.SEGPERM_EXEC:
        force_code(vaddr, size)

# --------------------------------------------------
# Parse symbols
# --------------------------------------------------

print("[+] Parsing symbols")

for i in range(SYMTAB_COUNT):
    ea = sym_ea + (i * 0x10)

    st_name  = u32(ea + 0x00)
    st_info  = ida_bytes.get_byte(ea + 0x04)
    st_other = ida_bytes.get_byte(ea + 0x05)
    st_shndx = ida_bytes.get_word(ea + 0x06)
    st_value = u64(ea + 0x08)
    st_size  = u64(ea + 0x10)
    

    if st_name == 0:
        continue

    name = read_cstr(str_ea + st_name)
    
    if not name:
        continue
        
    addr = st_value
    
    if is_end_of_image(addr):
        continue

    # addr = fix_thumb(addr)

    if addr < BASE + HDR_SIZE:   # avoid header region
        continue
        
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