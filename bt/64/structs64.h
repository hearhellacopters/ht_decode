struct header {   
  int PROHEADDIR_OFF __off;   
  int PROHEADDIR_COUNT;   
  int PT_DYNAMIC_OFF __off;   
  int PT_DYNAMIC_COUNT;   
  int STRTAB_OFF __off;   
  int STRTAB_COUNT;   
  int SYMTAB_OFF __off;   
  int SYMTAB_COUNT;   
  int REL_OFF __off;   
  int REL_COUNT;   
  int JMPREL_OFF __off;   
  int JMPREL_COUNT;   
  int gap30;   
  int gap34;   
  int MACHINE_TYPE;    
};

enum ELF_TYPE
{
  BLANK_0 = 0,
  MASTER_LIB_225 = 225,
  RW_LOAD_SEC_208 = 208,
  FILE_READER_154 = 154, // readFile & procSelfMaps functions from master
  LV0_M_226 = 226,
  
  LV0_129 = 129,
  LV0_150 = 150,
  LV0_RAWDATA_243 = 243,
  LV1_M_227 = 227,
  
  LV1_143 = 143, // error handling
  LV1_151 = 151,
  LV1_142 = 142,
  LV1_RAWDATA_244 = 244,
  LV2_M_228 = 228,
  
  LV2_2 = 2,
  LV2_106 = 106,
  LV2_105 = 105,
  LV2_96 = 96,
  LV2_64 = 64,
  LV2_32 = 32,
  LV2_84 = 84,
  LV2_51 = 51, ///< calls assets/57d5/data1.dat
  LV2_RAW_DATA_245 = 245,
  LV3_M_229 = 229,
  
  LV3_83 = 83,
  LV3_164 = 164,
  LV3_88 = 88,
  LV3_RAWADTA_246 = 246,
  LV4_M_230 = 230,
  
  LV4_3 = 3,
  LV4_160 = 160, ///< was blank
  LV4_RAWDATA_247 = 247,
  LV5_M_231 = 231,
  
  LV5_178 = 178,
  LV5_176 = 176,
  LV5_185 = 185, ///< was blank
  LV5_157 = 157, ///< Headers offset was blank
  LV5_158 = 158, ///< Headers offset was blank
  LV5_194 = 194, ///< was blank
  LV5_195 = 195, ///< was blank
  LV5_155 = 155,
  LV5_RAWDATA_248 = 248,
  LV6_M_232 = 232,
  
  LV7_M_152 = 152,
};

struct elfEntry
{
  ELF_TYPE ELFtype;
  int processCheck;
  __int64 ELFAddress;
  int ELFSize;
  int data14;
};

enum e_version32_e // 4 bytes
{ 
    EV_NONE    = 0x0,
    EV_CURRENT = 0x1,
};

enum e_machine32_e : __int16
{
  EM_NONE = 0x0,
  EM_M32 = 0x1,
  EM_SPARC = 0x2,
  EM_386 = 0x3,
  EM_68K = 0x4,
  EM_88K = 0x5,
  reserved6 = 0x6,
  EM_860 = 0x7,
  EM_MIPS = 0x8,
  EM_S370 = 0x9,
  EM_MIPS_RS3_LE = 0xA,
  reserved11 = 0xB,
  reserved12 = 0xC,
  reserved13 = 0xD,
  reserved14 = 0xE,
  EM_PARISC = 0xF,
  reserved16 = 0x10,
  EM_VPP500 = 0x11,
  EM_SPARC32PLUS = 0x12,
  EM_960 = 0x13,
  EM_PPC = 0x14,
  EM_PPC64 = 0x15,
  EM_S390 = 0x16,
  reserved23 = 0x17,
  reserved24 = 0x18,
  reserved25 = 0x19,
  reserved26 = 0x1A,
  reserved27 = 0x1B,
  reserved28 = 0x1C,
  reserved29 = 0x1D,
  reserved30 = 0x1E,
  reserved31 = 0x1F,
  reserved32 = 0x20,
  reserved33 = 0x21,
  reserved34 = 0x22,
  reserved35 = 0x23,
  EM_V800 = 0x24,
  EM_FR20 = 0x25,
  EM_RH32 = 0x26,
  EM_RCE = 0x27,
  EM_ARM = 0x28,
  EM_ALPHA = 0x29,
  EM_SH = 0x2A,
  EM_SPARCV9 = 0x2B,
  EM_TRICORE = 0x2C,
  EM_ARC = 0x2D,
  EM_H8_300 = 0x2E,
  EM_H8_300H = 0x2F,
  EM_H8S = 0x30,
  EM_H8_500 = 0x31,
  EM_IA_64 = 0x32,
  EM_MIPS_X = 0x33,
  EM_COLDFIRE = 0x34,
  EM_68HC12 = 0x35,
  EM_MMA = 0x36,
  EM_PCP = 0x37,
  EM_NCPU = 0x38,
  EM_NDR1 = 0x39,
  EM_STARCORE = 0x3A,
  EM_ME16 = 0x3B,
  EM_ST100 = 0x3C,
  EM_TINYJ = 0x3D,
  EM_X86_64 = 0x3E,
  EM_PDSP = 0x3F,
  EM_PDP10 = 0x40,
  EM_PDP11 = 0x41,
  EM_FX66 = 0x42,
  EM_ST9PLUS = 0x43,
  EM_ST7 = 0x44,
  EM_68HC16 = 0x45,
  EM_68HC11 = 0x46,
  EM_68HC08 = 0x47,
  EM_68HC05 = 0x48,
  EM_SVX = 0x49,
  EM_ST19 = 0x4B,
  EM_CRIS = 0x4C,
  EM_JAVELIN = 0x4D,
  EM_FIREPATH = 0x4E,
  EM_ZSP = 0x4F,
  EM_MMIX = 0x50,
  EM_HUANY = 0x51,
  EM_PRISM = 0x52,
  EM_AVR = 0x53,
  EM_FR30 = 0x54,
  EM_D10V = 0x55,
  EM_D30V = 0x56,
  EM_V850 = 0x57,
  EM_M32R = 0x58,
  EM_MN10300 = 0x59,
  EM_MN10200 = 0x5A,
  EM_PJ = 0x5B,
  EM_OPENRISC = 0x5C,
  EM_ARC_A5 = 0x5D,
  EM_XTENSA = 0x5E,
  EM_VIDEOCORE = 0x5F,
  EM_TMM_GPP = 0x60,
  EM_NS32K = 0x61,
  EM_TPC = 0x62,
  EM_SNP1K = 0x63,
  EM_ST200 = 0x64,
  EM_IP2K = 0x65,
  EM_MAX = 0x66,
  EM_CR = 0x67,
  EM_F2MC16 = 0x68,
  EM_MSP430 = 0x69,
  EM_BLACKFIN = 0x6A,
  EM_SE_C33 = 0x6B,
  EM_SEP = 0x6C,
  EM_ARCA = 0x6D,
  EM_UNICORE = 0x6E,
};

enum e_type32_e : __int16
{
  ET_NONE = 0x0,
  ET_REL = 0x1,
  ET_EXEC = 0x2,
  ET_DYN = 0x3,
  ET_CORE = 0x4,
  ET_LOOS = 0xFE00,
  ET_HIOS = 0xFEFF,
  ET_LOPROC = 0xFF00,
  ET_HIPROC = 0xFFFF,
};

enum ei_osabi_e : __int8
{ 
    ELFOSABI_NONE       = 0x0,
    ELFOSABI_HPUX       = 0x1,
    ELFOSABI_NETBSD     = 0x2,
    ELFOSABI_LINUX      = 0x3,
    ELFOSABI_SOLARIS    = 0x6,
    ELFOSABI_AIX        = 0x7,
    ELFOSABI_IRIX       = 0x8,
    ELFOSABI_FREEBSD    = 0x9,
    ELFOSABI_TRU64      = 0xA,
    ELFOSABI_MODESTO    = 0xB,
    ELFOSABI_OPENBSD    = 0xC,
    ELFOSABI_OPENVMS    = 0xD,
    ELFOSABI_NSK        = 0xE,
    ELFOSABI_AROS       = 0xF,
    ELFOSABI_ARM_AEABI  = 0x40,
    ELFOSABI_ARM        = 0x61,
    ELFOSABI_STANDALONE = 0xFF,
};

enum ei_version_e : __int8
{ 
    E_NONE    = 0x0,
    E_CURRENT = 0x1,
    E_NUM     = 0x2,
};

enum ei_data_e : __int8
{ 
    ELFDATANONE = 0x0,
    ELFDATA2LSB = 0x1,
    ELFDATA2MSB = 0x2,
    ELFDATANUM  = 0x3,
};

enum ei_class_2_e : __int8
{ 
    ELFCLASSNONE = 0x0,
    ELFCLASS32   = 0x1,
    ELFCLASS64   = 0x2,
    ELFCLASSNUM  = 0x3,
};

enum sh_type // 4 bytes
{ 
    SHT_NULL           = 0x0,
    SHT_PROGBITS       = 0x1,
    SHT_SYMTAB         = 0x2,
    SHT_STRTAB         = 0x3,
    SHT_RELA           = 0x4,
    SHT_HASH           = 0x5,
    SHT_DYNAMIC        = 0x6,
    SHT_NOTE           = 0x7,
    SHT_NOBITS         = 0x8,
    SHT_REL            = 0x9,
    SHT_SHLIB          = 0xA,
    SHT_DYNSYM         = 0xB,
    SHT_INIT_ARRAY     = 0xE,
    SHT_FINI_ARRAY     = 0xF,
    SHT_PREINIT_ARRAY  = 0x10,
    SHT_GROUP          = 0x11,
    SHT_SYMTAB_SHNDX   = 0x12,
    SHT_NUM            = 0x13,
    SHT_LOOS           = 0x60000000,
    SHT_GNU_ATTRIBUTES = 0x6FFFFFF5,
    SHT_GNU_HASH       = 0x6FFFFFF6,
    SHT_GNU_LIBLIST    = 0x6FFFFFF7,
    SHT_CHECKSUM       = 0x6FFFFFF8,
    SHT_LOSUNW         = 0x6FFFFFFA,
    SHT_SUNW_move      = 0x6FFFFFFA,
    SHT_SUNW_COMDAT    = 0x6FFFFFFB,
    SHT_SUNW_syminfo   = 0x6FFFFFFC,
    SHT_GNU_verdef     = 0x6FFFFFFD,
    SHT_GNU_verneed    = 0x6FFFFFFE,
    SHT_GNU_versym     = 0x6FFFFFFF,
    SHT_HISUNW         = 0x6FFFFFFF,
    SHT_HIOS           = 0x6FFFFFFF,
    SHT_LOPROC         = 0x70000000,
    SHT_HIPROC         = 0x7FFFFFFF,
    SHT_LOUSER         = 0x80000000,
    SHT_HIUSER         = 0x8FFFFFFF,
};

enum __bitmask sh_flags : __int64
{
  SHF_WRITE = 0x1LL,
  SHF_ALLOC = 0x2LL,
  SHF_EXECINSTR = 0x4LL,
  SHF_MERGE = 0x10LL,
  SHF_STRINGS = 0x20LL,
  SHF_INFO_LINK = 0x40LL,
  SHF_LINK_ORDER = 0x80LL,
  SHF_OS_NONCONFORMING = 0x100LL,
  SHF_GROUP = 0x200LL,
  SHF_TLS = 0x400LL,
  SHF_MASKOS = 0xFF00000LL,
  SHF_MASKPROC = 0xF0000000LL,          ///< MASK
  SHF_ORDERED = 0x40000000LL,
  SHF_EXCLUDE = 0x80000000LL,
};

struct __attribute__((packed)) Elf64_Shdr
{
  unsigned __int32 st_name __offset(OFF32,0xB6E4B);
  sh_type sh_type;
  sh_flags sh_flags;
  __int64 sh_addr __off;
  __int64 sh_offset __off;
  __int64 sh_size;
  int sh_link;
  int sh_info;
  __int64 sh_addralign;
  __int64 sh_entsize;
};

struct ELFHeader
{
  char magic[4];
  ei_class_2_e ei_class_2;
  ei_data_e ei_data;
  ei_version_e ei_version;
  ei_osabi_e ei_osabi;
  unsigned __int8 ei_abiversion;
  unsigned __int8 ei_pad[6];
  unsigned __int8 ei_nident_SIZE;
  e_type32_e e_type;
  e_machine32_e e_machine;
  e_version32_e e_version;
  char *e_entry_START_ADDRESS;
  Elf64_Phdr *e_phoff_PROGRAM_HEADER_OFFSET_IN_FILE;
  Elf64_Shdr *e_shoff_SECTION_HEADER_OFFSET_IN_FILE;
  int e_flags;
  __int16 e_ehsize_ELF_HEADER_SIZE;
  __int16 e_phentsize_PROGRAM_HEADER_ENTRY_SIZE_IN_FILE;
  __int16 e_phnum_NUMBER_OF_PROGRAM_HEADER_ENTRIES;
  __int16 e_shentsize_SECTION_HEADER_ENTRY_SIZE;
  __int16 e_shnum_NUMBER_OF_SECTION_HEADER_ENTRIES;
  __int16 e_shtrndx_STRING_TABLE_INDEX;
};

struct libHeaderParse
{
  ELFHeader *processStartingAddress;
  _QWORD ELFSize;
  header *returnNextELFAddress;
  _QWORD maxAddress;
  header *PT_LOADp_vaddr;
  ELFHeader *processStartingAddress2;
  Elf64_Phdr *e_phoff_PROGRAM_HEADER_OFFSET_IN_FILE;
  __int64 e_phnum_NUMBER_OF_PROGRAM_HEADER_ENTRIES;
  Elf64_Shdr *secTableStart;
  __int64 secTableCount;
  __int64 e_shtrndx_STRING_TABLE_INDEX;
  Elf64_Dyn *PT_DYNAMIC;
  __int64 DYNAMIC_COUNT;
  Elf64_Rela *hashEntry;
  __int64 hashSize;
  Elf64_Rela *gnuHashEntry;
  __int64 gnuHashSize;
  Elf64_Rela *REL_ENTRY;
  __int64 REL_SIZE;
  Elf64_Rela *JMPREL_ENTRY;
  __int64 JMPREL_SIZE;
  Elf64_Sym *DynSymStart;
  __int64 DynSymSize;
  char *DynStrTable;
  __int64 DynStrSize;
  __int64 VersionSymbolEntry;
  __int64 VersionSymbolCount;
  __int64 VersionSymbolSize;
  __int64 verDefEntry;
  __int64 verDefCount;
  __int64 verDefSize;
  __int64 verNeededEntry;
  __int64 verNeededCount;
  __int64 verNeededSize;
  _BYTE usePHTOffset;
  _BYTE byte111;
  _BYTE byte112;
  _BYTE byte113;
  _DWORD e_machine;
  char libPathString[1024];
};

struct masterLibHeadersParse
{
  libHeaderParse libHeaderData;
  libHeaderParse *libHeadersArray;
  __int64 libHeadersCount;
};

struct nextStartUp
{
  _QWORD data00;
  _QWORD data08;
  _QWORD data10;
  _QWORD data18;
  _QWORD data20;
  _QWORD data28;
  _QWORD data30;
  _QWORD data38;
  _QWORD data40;
  _QWORD data48;
  _QWORD data50;
  _QWORD data58;
  _QWORD data60;
  _QWORD data68;
  _QWORD data70;
  _QWORD data78;
  _QWORD data80;
  _QWORD data88;
  _QWORD data90;
  _QWORD data98;
  _QWORD dataA0;
  _QWORD dataA8;
  _QWORD a7;
  _QWORD a8;
  _QWORD a5;
  _QWORD a6;
  _QWORD a3;
  _QWORD a4;
  elfEntry *elfEntries;
  _QWORD a2;
};

struct startUp
{
  startUp *startUp;
  _QWORD processStartingAddress;
  masterLibHeadersParse *libHeadersData;
  nextStartUp *nextStartUp;
  _QWORD data20;
  _QWORD data28;
  _QWORD data30;
  _QWORD data38;
  _QWORD data40;
  _QWORD data48;
  _QWORD data50;
  _QWORD data58;
  _QWORD data60;
  _QWORD data68;
  _QWORD data70;
  _QWORD data78;
  _QWORD data80;
  _QWORD data88;
  _QWORD data90;
  _QWORD data98;
  _QWORD dataA0;
  _QWORD dataA8;
  _QWORD a7;
  _QWORD a8;
  _QWORD a5;
  _QWORD a6;
  _QWORD a3;
  _QWORD a4;
  _QWORD a1;
  _QWORD a2;
};

struct masterStartUp
{
  masterStartUp *startUp;
  _QWORD processStartingAddress;
  masterLibHeadersParse *libHeadersData;
  nextStartUp *newStartUp;
  _QWORD data20;
  _QWORD data28;
  _QWORD data30;
  _QWORD data38;
  _QWORD data40;
  _QWORD data48;
  _QWORD data50;
  _QWORD data58;
  _QWORD data60;
  _QWORD data68;
  _QWORD data70;
  _QWORD data78;
  _QWORD data80;
  _QWORD data88;
  _QWORD data90;
  _QWORD data98;
  _QWORD dataA0;
  _QWORD dataA8;
  _QWORD a7;
  _QWORD a8;
  _QWORD a5;
  _QWORD a6;
  _QWORD a3;
  _QWORD a4;
  _QWORD a1;
  _QWORD a2;
};

struct subTable
{
  int elfType;
  int processCheck;
  int sliceTableOffset;
  int sliceTableSize;
  char *ELFHeadersOffset;
  int ELFHeadersSize;
  int elfType2;
  int offsetPassoffFunc;
  int offsetSetELFEntries;
  int data24;
  int data28;
  int data2C;
  int data30;
  int data34;
  int data38;
  int data3C;
  int data40;
  int data44;
  int data48;
  int data4C;
  int data50;
  int data54;
  int data58;
};

struct errorBuffer
{
  int wasFatal;
  int errorIndex;
  int memoryNeeded;
  int dataC;
  char str[36];
  int data34;
  int data38;
  int data3C;
  int line;
  int lineFileType;
  int errNo;
  int data4C;  ///< checked & 0x10000 != 0
};

enum systemcall : __int64
{
  io_setup = 0x0LL,
  io_destroy = 0x1LL,
  io_submit = 0x2LL,
  io_cancel = 0x3LL,
  io_getevents = 0x4LL,
  setxattr = 0x5LL,
  lsetxattr = 0x6LL,
  fsetxattr = 0x7LL,
  getxattr = 0x8LL,
  lgetxattr = 0x9LL,
  fgetxattr = 0xALL,
  listxattr = 0xBLL,
  llistxattr = 0xCLL,
  flistxattr = 0xDLL,
  removexattr = 0xELL,
  lremovexattr = 0xFLL,
  fremovexattr = 0x10LL,
  getcwd = 0x11LL,
  lookup_dcookie = 0x12LL,
  eventfd2 = 0x13LL,
  epoll_create1 = 0x14LL,
  epoll_ctl = 0x15LL,
  epoll_pwait = 0x16LL,
  dup = 0x17LL,
  dup3 = 0x18LL,
  fcntl = 0x19LL,
  inotify_init1 = 0x1ALL,
  inotify_add_watch = 0x1BLL,
  inotify_rm_watch = 0x1CLL,
  ioctl = 0x1DLL,
  ioprio_set = 0x1ELL,
  ioprio_get = 0x1FLL,
  flock = 0x20LL,
  mknodat = 0x21LL,
  mkdirat = 0x22LL,
  unlinkat = 0x23LL,
  symlinkat = 0x24LL,
  linkat = 0x25LL,
  renameat = 0x26LL,
  umount2 = 0x27LL,
  mount = 0x28LL,
  pivot_root = 0x29LL,
  nfsservctl = 0x2ALL,
  statfs = 0x2BLL,
  fstatfs = 0x2CLL,
  truncate = 0x2DLL,
  ftruncate = 0x2ELL,
  fallocate = 0x2FLL,
  faccessat = 0x30LL,
  chdir = 0x31LL,
  fchdir = 0x32LL,
  chroot = 0x33LL,
  fchmod = 0x34LL,
  fchmodat = 0x35LL,
  fchownat = 0x36LL,
  fchown = 0x37LL,
  openat = 0x38LL,
  close = 0x39LL,
  vhangup = 0x3ALL,
  pipe2 = 0x3BLL,
  quotactl = 0x3CLL,
  getdents64 = 0x3DLL,
  lseek = 0x3ELL,
  read = 0x3FLL,
  write = 0x40LL,
  readv = 0x41LL,
  writev = 0x42LL,
  pread64 = 0x43LL,
  pwrite64 = 0x44LL,
  preadv = 0x45LL,
  pwritev = 0x46LL,
  sendfile = 0x47LL,
  pselect6 = 0x48LL,
  ppoll = 0x49LL,
  signalfd4 = 0x4ALL,
  vmsplice = 0x4BLL,
  splice = 0x4CLL,
  tee = 0x4DLL,
  readlinkat = 0x4ELL,
  newfstatat = 0x4FLL,
  fstat = 0x50LL,
  sync = 0x51LL,
  fsync = 0x52LL,
  fdatasync = 0x53LL,
  sync_file_range = 0x54LL,
  timerfd_create = 0x55LL,
  timerfd_settime = 0x56LL,
  timerfd_gettime = 0x57LL,
  utimensat = 0x58LL,
  acct = 0x59LL,
  capget = 0x5ALL,
  capset = 0x5BLL,
  personality = 0x5CLL,
  exit = 0x5DLL,
  exit_group = 0x5ELL,
  waitid = 0x5FLL,
  set_tid_address = 0x60LL,
  unshare = 0x61LL,
  futex = 0x62LL,
  set_robust_list = 0x63LL,
  get_robust_list = 0x64LL,
  nanosleep = 0x65LL,
  getitimer = 0x66LL,
  setitimer = 0x67LL,
  kexec_load = 0x68LL,
  init_module = 0x69LL,
  delete_module = 0x6ALL,
  timer_create = 0x6BLL,
  timer_gettime = 0x6CLL,
  timer_getoverrun = 0x6DLL,
  timer_settime = 0x6ELL,
  timer_delete = 0x6FLL,
  clock_settime = 0x70LL,
  clock_gettime = 0x71LL,
  clock_getres = 0x72LL,
  clock_nanosleep = 0x73LL,
  syslog = 0x74LL,
  ptrace = 0x75LL,
  sched_setparam = 0x76LL,
  sched_setscheduler = 0x77LL,
  sched_getscheduler = 0x78LL,
  sched_getparam = 0x79LL,
  sched_setaffinity = 0x7ALL,
  sched_getaffinity = 0x7BLL,
  sched_yield = 0x7CLL,
  sched_get_priority_max = 0x7DLL,
  sched_get_priority_min = 0x7ELL,
  sched_rr_get_interval = 0x7FLL,
  restart_syscall = 0x80LL,
  kill = 0x81LL,
  tkill = 0x82LL,
  tgkill = 0x83LL,
  sigaltstack = 0x84LL,
  rt_sigsuspend = 0x85LL,
  rt_sigaction = 0x86LL,
  rt_sigprocmask = 0x87LL,
  rt_sigpending = 0x88LL,
  rt_sigtimedwait = 0x89LL,
  rt_sigqueueinfo = 0x8ALL,
  rt_sigreturn = 0x8BLL,
  setpriority = 0x8CLL,
  getpriority = 0x8DLL,
  reboot = 0x8ELL,
  setregid = 0x8FLL,
  setgid = 0x90LL,
  setreuid = 0x91LL,
  setuid = 0x92LL,
  setresuid = 0x93LL,
  getresuid = 0x94LL,
  setresgid = 0x95LL,
  getresgid = 0x96LL,
  setfsuid = 0x97LL,
  setfsgid = 0x98LL,
  times = 0x99LL,
  setpgid = 0x9ALL,
  getpgid = 0x9BLL,
  getsid = 0x9CLL,
  setsid = 0x9DLL,
  getgroups = 0x9ELL,
  setgroups = 0x9FLL,
  uname = 0xA0LL,
  sethostname = 0xA1LL,
  setdomainname = 0xA2LL,
  getrlimit = 0xA3LL,
  setrlimit = 0xA4LL,
  getrusage = 0xA5LL,
  umask = 0xA6LL,
  prctl = 0xA7LL,
  getcpu = 0xA8LL,
  gettimeofday = 0xA9LL,
  settimeofday = 0xAALL,
  adjtimex = 0xABLL,
  getpid = 0xACLL,
  getppid = 0xADLL,
  getuid = 0xAELL,
  geteuid = 0xAFLL,
  getgid = 0xB0LL,
  getegid = 0xB1LL,
  gettid = 0xB2LL,
  sysinfo = 0xB3LL,
  mq_open = 0xB4LL,
  mq_unlink = 0xB5LL,
  mq_timedsend = 0xB6LL,
  mq_timedreceive = 0xB7LL,
  mq_notify = 0xB8LL,
  mq_getsetattr = 0xB9LL,
  msgget = 0xBALL,
  msgctl = 0xBBLL,
  msgrcv = 0xBCLL,
  msgsnd = 0xBDLL,
  semget = 0xBELL,
  semctl = 0xBFLL,
  semtimedop = 0xC0LL,
  semop = 0xC1LL,
  shmget = 0xC2LL,
  shmctl = 0xC3LL,
  shmat = 0xC4LL,
  shmdt = 0xC5LL,
  socket = 0xC6LL,
  socketpair = 0xC7LL,
  bind = 0xC8LL,
  listen = 0xC9LL,
  accept = 0xCALL,
  connect = 0xCBLL,
  getsockname = 0xCCLL,
  getpeername = 0xCDLL,
  sendto = 0xCELL,
  recvfrom = 0xCFLL,
  setsockopt = 0xD0LL,
  getsockopt = 0xD1LL,
  shutdown = 0xD2LL,
  sendmsg = 0xD3LL,
  recvmsg = 0xD4LL,
  readahead = 0xD5LL,
  brk = 0xD6LL,
  munmap = 0xD7LL,
  mremap = 0xD8LL,
  add_key = 0xD9LL,
  request_key = 0xDALL,
  keyctl = 0xDBLL,
  clone = 0xDCLL,
  execve = 0xDDLL,
  mmap = 0xDELL,
  fadvise64 = 0xDFLL,
  swapon = 0xE0LL,
  swapoff = 0xE1LL,
  mprotect = 0xE2LL,
  msync = 0xE3LL,
  mlock = 0xE4LL,
  munlock = 0xE5LL,
  mlockall = 0xE6LL,
  munlockall = 0xE7LL,
  mincore = 0xE8LL,
  madvise = 0xE9LL,
  remap_file_pages = 0xEALL,
  mbind = 0xEBLL,
  get_mempolicy = 0xECLL,
  set_mempolicy = 0xEDLL,
  migrate_pages = 0xEELL,
  move_pages = 0xEFLL,
  rt_tgsigqueueinfo = 0xF0LL,
  perf_event_open = 0xF1LL,
  accept4 = 0xF2LL,
  recvmmsg = 0xF3LL,
  wait4 = 0x104LL,
  prlimit64 = 0x105LL,
  fanotify_init = 0x106LL,
  fanotify_mark = 0x107LL,
  name_to_handle_at = 0x108LL,
  open_by_handle_at = 0x109LL,
  clock_adjtime = 0x10ALL,
  syncfs = 0x10BLL,
  setns = 0x10CLL,
  sendmmsg = 0x10DLL,
  process_vm_readv = 0x10ELL,
  process_vm_writev = 0x10FLL,
  kcmp = 0x110LL,
  finit_module = 0x111LL,
  sched_setattr = 0x112LL,
  sched_getattr = 0x113LL,
  renameat2 = 0x114LL,
  seccomp = 0x115LL,
  getrandom = 0x116LL,
  memfd_create = 0x117LL,
  bpf = 0x118LL,
  execveat = 0x119LL,
  userfaultfd = 0x11ALL,
  membarrier = 0x11BLL,
  mlock2 = 0x11CLL,
  copy_file_range = 0x11DLL,
  preadv2 = 0x11ELL,
  pwritev2 = 0x11FLL,
  pkey_mprotect = 0x120LL,
  pkey_alloc = 0x121LL,
  pkey_free = 0x122LL,
  statx = 0x123LL,
  io_pgetevents = 0x124LL,
  rseq = 0x125LL,
  kexec_file_load = 0x126LL,
  pidfd_send_signal = 0x1A8LL,
  io_uring_setup = 0x1A9LL,
  io_uring_enter = 0x1AALL,
  io_uring_register = 0x1ABLL,
  open_tree = 0x1ACLL,
  move_mount = 0x1ADLL,
  fsopen = 0x1AELL,
  fsconfig = 0x1AFLL,
  fsmount = 0x1B0LL,
  fspick = 0x1B1LL,
  pidfd_open = 0x1B2LL,
  clone3 = 0x1B3LL,
  close_range = 0x1B4LL,
  faccessat2 = 0x1B7LL,
};

struct ELFAddressByType
{
  ELF_TYPE type;
  int address;
};

struct readFile
{
    void *buffer;
    __int64 size;
};

struct __attribute__((packed)) procParse
{
  char *processStartAddress;
  void *addressRange;
  void *offsetValue;
  _DWORD permFlags;
  _DWORD privateOrSharedValue;
  _DWORD dev1value;
  _DWORD dev2value;
  _DWORD inode;
  char ProcessPathStr[1024];
};

struct stat64
{
  unsigned __int64 st_dev;
  unsigned __int64 st_ino;
  unsigned int st_mode;
  unsigned int st_nlink;
  unsigned int st_uid;
  unsigned int st_gid;
  unsigned __int64 st_rdev;
  unsigned __int64 __pad1;
  __int64 st_size;
  int st_blksize;
  int __pad2;
  __int64 st_blocks;
  int st_atime;
  unsigned int st_atime_nsec;
  int st_mtime;
  unsigned int st_mtime_nsec;
  int st_ctime;
  unsigned int st_ctime_nsec;
  unsigned int __unused4;
  unsigned int __unused5;
};
