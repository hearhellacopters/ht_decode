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
  int ELFAddress;
  int ELFSize;
};

struct startUp
{
  _DWORD argc;
  _DWORD argv;
  _DWORD envp;
  _DWORD enva;
};

enum e_version32_e // 4 bytes
{                                       // XREF: ELFHeader.e_version32/r
    EV_NONE    = 0x0,
    EV_CURRENT = 0x1,
};

enum e_machine32_e : __int16
{                                       // XREF: ELFHeader.e_machine32/r
    EM_NONE        = 0x0,
    EM_M32         = 0x1,
    EM_SPARC       = 0x2,
    EM_386         = 0x3,
    EM_68K         = 0x4,
    EM_88K         = 0x5,
    reserved6      = 0x6,
    EM_860         = 0x7,
    EM_MIPS        = 0x8,
    EM_S370        = 0x9,
    EM_MIPS_RS3_LE = 0xA,
    reserved11     = 0xB,
    reserved12     = 0xC,
    reserved13     = 0xD,
    reserved14     = 0xE,
    EM_PARISC      = 0xF,
    reserved16     = 0x10,
    EM_VPP500      = 0x11,
    EM_SPARC32PLUS = 0x12,
    EM_960         = 0x13,
    EM_PPC         = 0x14,
    EM_PPC64       = 0x15,
    EM_S390        = 0x16,
    reserved23     = 0x17,
    reserved24     = 0x18,
    reserved25     = 0x19,
    reserved26     = 0x1A,
    reserved27     = 0x1B,
    reserved28     = 0x1C,
    reserved29     = 0x1D,
    reserved30     = 0x1E,
    reserved31     = 0x1F,
    reserved32     = 0x20,
    reserved33     = 0x21,
    reserved34     = 0x22,
    reserved35     = 0x23,
    EM_V800        = 0x24,
    EM_FR20        = 0x25,
    EM_RH32        = 0x26,
    EM_RCE         = 0x27,
    EM_ARM         = 0x28,
    EM_ALPHA       = 0x29,
    EM_SH          = 0x2A,
    EM_SPARCV9     = 0x2B,
    EM_TRICORE     = 0x2C,
    EM_ARC         = 0x2D,
    EM_H8_300      = 0x2E,
    EM_H8_300H     = 0x2F,
    EM_H8S         = 0x30,
    EM_H8_500      = 0x31,
    EM_IA_64       = 0x32,
    EM_MIPS_X      = 0x33,
    EM_COLDFIRE    = 0x34,
    EM_68HC12      = 0x35,
    EM_MMA         = 0x36,
    EM_PCP         = 0x37,
    EM_NCPU        = 0x38,
    EM_NDR1        = 0x39,
    EM_STARCORE    = 0x3A,
    EM_ME16        = 0x3B,
    EM_ST100       = 0x3C,
    EM_TINYJ       = 0x3D,
    EM_X86_64      = 0x3E,
    EM_PDSP        = 0x3F,
    EM_PDP10       = 0x40,
    EM_PDP11       = 0x41,
    EM_FX66        = 0x42,
    EM_ST9PLUS     = 0x43,
    EM_ST7         = 0x44,
    EM_68HC16      = 0x45,
    EM_68HC11      = 0x46,
    EM_68HC08      = 0x47,
    EM_68HC05      = 0x48,
    EM_SVX         = 0x49,
    EM_ST19        = 0x4B,
    EM_CRIS        = 0x4C,
    EM_JAVELIN     = 0x4D,
    EM_FIREPATH    = 0x4E,
    EM_ZSP         = 0x4F,
    EM_MMIX        = 0x50,
    EM_HUANY       = 0x51,
    EM_PRISM       = 0x52,
    EM_AVR         = 0x53,
    EM_FR30        = 0x54,
    EM_D10V        = 0x55,
    EM_D30V        = 0x56,
    EM_V850        = 0x57,
    EM_M32R        = 0x58,
    EM_MN10300     = 0x59,
    EM_MN10200     = 0x5A,
    EM_PJ          = 0x5B,
    EM_OPENRISC    = 0x5C,
    EM_ARC_A5      = 0x5D,
    EM_XTENSA      = 0x5E,
    EM_VIDEOCORE   = 0x5F,
    EM_TMM_GPP     = 0x60,
    EM_NS32K       = 0x61,
    EM_TPC         = 0x62,
    EM_SNP1K       = 0x63,
    EM_ST200       = 0x64,
    EM_IP2K        = 0x65,
    EM_MAX         = 0x66,
    EM_CR          = 0x67,
    EM_F2MC16      = 0x68,
    EM_MSP430      = 0x69,
    EM_BLACKFIN    = 0x6A,
    EM_SE_C33      = 0x6B,
    EM_SEP         = 0x6C,
    EM_ARCA        = 0x6D,
    EM_UNICORE     = 0x6E,
};

enum e_type32_e : __int16
{                                       // XREF: ELFHeader.e_type32/r
    ET_NONE   = 0x0,
    ET_REL    = 0x1,
    ET_EXEC   = 0x2,
    ET_DYN    = 0x3,
    ET_CORE   = 0x4,
    ET_LOOS   = 0xFE00,
    ET_HIOS   = 0xFEFF,
    ET_LOPROC = 0xFF00,
    ET_HIPROC = 0xFFFF,
};

enum ei_osabi_e : __int8
{                                       // XREF: ELFHeader.ei_osabi/r
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
{                                       // XREF: ELFHeader.ei_version/r
    E_NONE    = 0x0,
    E_CURRENT = 0x1,
    E_NUM     = 0x2,
};

enum ei_data_e : __int8
{                                       // XREF: ELFHeader.ei_data/r
    ELFDATANONE = 0x0,
    ELFDATA2LSB = 0x1,
    ELFDATA2MSB = 0x2,
    ELFDATANUM  = 0x3,
};

enum ei_class_2_e : __int8
{                                       // XREF: ELFHeader.ei_class_2/r
    ELFCLASSNONE = 0x0,
    ELFCLASS32   = 0x1,
    ELFCLASS64   = 0x2,
    ELFCLASSNUM  = 0x3,
};

enum sh_type // 4 bytes
{                                       // XREF: Elf32_Shdr.sh_type/r
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

enum __bitmask sh_flags // 4 bytes
{                                       // XREF: Elf32_Shdr.sh_flags/r
    SHF_WRITE            = 0x1,
    SHF_ALLOC            = 0x2,
    SHF_EXECINSTR        = 0x4,
    SHF_MERGE            = 0x10,
    SHF_STRINGS          = 0x20,
    SHF_INFO_LINK        = 0x40,
    SHF_LINK_ORDER       = 0x80,
    SHF_OS_NONCONFORMING = 0x100,
    SHF_GROUP            = 0x200,
    SHF_TLS              = 0x400,
    SHF_MASKOS           = 0xFF00000,
    SHF_MASKPROC         = 0xF0000000,  // MASK
    SHF_ORDERED          = 0x40000000,
    SHF_EXCLUDE          = 0x80000000,
};

struct Elf32_Shdr // sizeof=0x28
{
    unsigned __int32 st_name __offset(OFF32,0xB6E4B);
    sh_type sh_type;
    sh_flags sh_flags;
    int sh_addr __off;
    int sh_offset __off;
    int sh_size;
    int sh_link;
    int sh_info;
    int sh_addralign;
    int sh_entsize;
};

struct ELFHeader
{
  char magic[4];
  ei_class_2_e ei_class_2;
  ei_data_e ei_data;
  ei_version_e ei_version;
  ei_osabi_e ei_osabi;
  char ei_abiversion;
  char ei_pad[6];
  char ei_nident_SIZE;
  e_type32_e e_type32;
  e_machine32_e e_machine32;
  e_version32_e e_version32;
  char *e_entry_START_ADDRESS;
  Elf32_Phdr *e_phoff_PROGRAM_HEADER_OFFSET_IN_FILE;
  Elf32_Shdr *e_shoff_SECTION_HEADER_OFFSET_IN_FILE;
  int e_flags;
  unsigned __int16 e_ehsize_ELF_HEADER_SIZE;
  unsigned __int16 e_phentsize_PROGRAM_HEADER_ENTRY_SIZE_IN_FILE;
  unsigned __int16 e_phnum_NUMBER_OF_PROGRAM_HEADER_ENTRIES;
  unsigned __int16 e_shentsize_SECTION_HEADER_ENTRY_SIZE;
  unsigned __int16 e_shnum_NUMBER_OF_SECTION_HEADER_ENTRIES;
  unsigned __int16 e_shtrndx_STRING_TABLE_INDEX;
};

struct libHeaderParse
{
  ELFHeader *processStartingAddress;
  int ELFSize;
  header *returnNextELFAddress;
  int maxAddress;
  header *returnNextELFAddress2;
  ELFHeader *processStartingAddress2;
  Elf32_Phdr *e_phoff_PROGRAM_HEADER_OFFSET_IN_FILE;
  int e_phnum_NUMBER_OF_PROGRAM_HEADER_ENTRIES;
  int secTableStart;
  int secTableCount;
  int e_shtrndx_STRING_TABLE_INDEX;
  Elf32_Dyn *PT_DYNAMIC;
  int DYNAMIC_COUNT;
  unsigned int *hashEntry;
  int hashSize;
  char *gnuHashEntry;
  int gnuHashSize;
  Elf32_Rel *REL_ENTRY;
  int REL_SIZE;
  Elf32_Rel *JMPREL_ENTRY;
  int JMPREL_SIZE;
  Elf32_Sym *DynSymStart;
  int DynSymSize;
  char *DynStrTable;
  int DynStrSize;
  int VersionSymbolEntry;
  int VersionSymbolCount;
  int VersionSymbolSize;
  int verDefEntry;
  int verDefCount;
  int verDefSize;
  int verNeededEntry;
  int verNeededCount;
  int verNeededSize;
  char usePHTOffset;
  char data89;
  char data8A;
  char data8B;
  int e_machine32;
  char libPathString[1024];
};

struct masterLibHeadersParse
{
  libHeaderParse libHeaderData;
  libHeaderParse *libHeadersArray;
  int libHeadersCount;
};

struct nextStartUp
{
  _DWORD data0;
  _DWORD continueCheck;
  _DWORD maybe208;
  elfEntry *elfEntries;
  elfEntry **p_elfEntry;
};

struct masterStartUp
{
  startUp *startUp;
  _DWORD processStartingAddress;
  masterLibHeadersParse *libHeadersData;
  nextStartUp *nextStartUp;
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

enum systemcall
{
  restart_syscall = 0x0,
  exit = 0x1,
  fork = 0x2,
  read = 0x3,
  write = 0x4,
  open = 0x5,
  close = 0x6,
  creat = 0x8,
  link = 0x9,
  unlink = 0xA,
  execve = 0xB,
  chdir = 0xC,
  mknod = 0xE,
  chmod = 0xF,
  lchown = 0x10,
  lseek = 0x13,
  getpid = 0x14,
  mount = 0x15,
  setuid = 0x17,
  getuid = 0x18,
  ptrace = 0x1A,
  pause = 0x1D,
  access = 0x21,
  nice = 0x22,
  sync = 0x24,
  kill = 0x25,
  rename = 0x26,
  mkdir = 0x27,
  rmdir = 0x28,
  dup = 0x29,
  pipe = 0x2A,
  times = 0x2B,
  brk = 0x2D,
  setgid = 0x2E,
  getgid = 0x2F,
  geteuid = 0x31,
  getegid = 0x32,
  acct = 0x33,
  umount2 = 0x34,
  ioctl = 0x36,
  fcntl = 0x37,
  setpgid = 0x39,
  umask = 0x3C,
  chroot = 0x3D,
  ustat = 0x3E,
  dup2 = 0x3F,
  getppid = 0x40,
  getpgrp = 0x41,
  setsid = 0x42,
  sigaction = 0x43,
  setreuid = 0x46,
  setregid = 0x47,
  sigsuspend = 0x48,
  sigpending = 0x49,
  sethostname = 0x4A,
  setrlimit = 0x4B,
  getrusage = 0x4D,
  gettimeofday = 0x4E,
  settimeofday = 0x4F,
  getgroups = 0x50,
  setgroups = 0x51,
  symlink = 0x53,
  readlink = 0x55,
  uselib = 0x56,
  swapon = 0x57,
  reboot = 0x58,
  munmap = 0x5B,
  truncate = 0x5C,
  ftruncate = 0x5D,
  fchmod = 0x5E,
  fchown = 0x5F,
  getpriority = 0x60,
  setpriority = 0x61,
  statfs = 0x63,
  fstatfs = 0x64,
  syslog = 0x67,
  setitimer = 0x68,
  getitimer = 0x69,
  stat = 0x6A,
  lstat = 0x6B,
  fstat = 0x6C,
  vhangup = 0x6F,
  wait4 = 0x72,
  swapoff = 0x73,
  sysinfo = 0x74,
  fsync = 0x76,
  sigreturn = 0x77,
  clone = 0x78,
  setdomainname = 0x79,
  uname = 0x7A,
  adjtimex = 0x7C,
  mprotect = 0x7D,
  sigprocmask = 0x7E,
  init_module = 0x80,
  delete_module = 0x81,
  quotactl = 0x83,
  getpgid = 0x84,
  fchdir = 0x85,
  bdflush = 0x86,
  sysfs = 0x87,
  personality = 0x88,
  setfsuid = 0x8A,
  setfsgid = 0x8B,
  _llseek = 0x8C,
  getdents = 0x8D,
  _newselect = 0x8E,
  flock = 0x8F,
  msync = 0x90,
  readv = 0x91,
  writev = 0x92,
  getsid = 0x93,
  fdatasync = 0x94,
  _sysctl = 0x95,
  mlock = 0x96,
  munlock = 0x97,
  mlockall = 0x98,
  munlockall = 0x99,
  sched_setparam = 0x9A,
  sched_getparam = 0x9B,
  sched_setscheduler = 0x9C,
  sched_getscheduler = 0x9D,
  sched_yield = 0x9E,
  sched_get_priority_max = 0x9F,
  sched_get_priority_min = 0xA0,
  sched_rr_get_interval = 0xA1,
  nanosleep = 0xA2,
  mremap = 0xA3,
  setresuid = 0xA4,
  getresuid = 0xA5,
  poll = 0xA8,
  nfsservctl = 0xA9,
  setresgid = 0xAA,
  getresgid = 0xAB,
  prctl = 0xAC,
  rt_sigreturn = 0xAD,
  rt_sigaction = 0xAE,
  rt_sigprocmask = 0xAF,
  rt_sigpending = 0xB0,
  rt_sigtimedwait = 0xB1,
  rt_sigqueueinfo = 0xB2,
  rt_sigsuspend = 0xB3,
  pread64 = 0xB4,
  pwrite64 = 0xB5,
  chown = 0xB6,
  getcwd = 0xB7,
  capget = 0xB8,
  capset = 0xB9,
  sigaltstack = 0xBA,
  sendfile = 0xBB,
  vfork = 0xBE,
  ugetrlimit = 0xBF,
  mmap2 = 0xC0,
  truncate64 = 0xC1,
  ftruncate64 = 0xC2,
  stat64 = 0xC3,
  lstat64 = 0xC4,
  fstat64 = 0xC5,
  lchown32 = 0xC6,
  getuid32 = 0xC7,
  getgid32 = 0xC8,
  geteuid32 = 0xC9,
  getegid32 = 0xCA,
  setreuid32 = 0xCB,
  setregid32 = 0xCC,
  getgroups32 = 0xCD,
  setgroups32 = 0xCE,
  fchown32 = 0xCF,
  setresuid32 = 0xD0,
  getresuid32 = 0xD1,
  setresgid32 = 0xD2,
  getresgid32 = 0xD3,
  chown32 = 0xD4,
  setuid32 = 0xD5,
  setgid32 = 0xD6,
  setfsuid32 = 0xD7,
  setfsgid32 = 0xD8,
  getdents64 = 0xD9,
  pivot_root = 0xDA,
  mincore = 0xDB,
  madvise = 0xDC,
  fcntl64 = 0xDD,
  gettid = 0xE0,
  readahead = 0xE1,
  setxattr = 0xE2,
  lsetxattr = 0xE3,
  fsetxattr = 0xE4,
  getxattr = 0xE5,
  lgetxattr = 0xE6,
  fgetxattr = 0xE7,
  listxattr = 0xE8,
  llistxattr = 0xE9,
  flistxattr = 0xEA,
  removexattr = 0xEB,
  lremovexattr = 0xEC,
  fremovexattr = 0xED,
  tkill = 0xEE,
  sendfile64 = 0xEF,
  futex = 0xF0,
  sched_setaffinity = 0xF1,
  sched_getaffinity = 0xF2,
  io_setup = 0xF3,
  io_destroy = 0xF4,
  io_getevents = 0xF5,
  io_submit = 0xF6,
  io_cancel = 0xF7,
  exit_group = 0xF8,
  lookup_dcookie = 0xF9,
  epoll_create = 0xFA,
  epoll_ctl = 0xFB,
  epoll_wait = 0xFC,
  remap_file_pages = 0xFD,
  set_tid_address = 0x100,
  timer_create = 0x101,
  timer_settime = 0x102,
  timer_gettime = 0x103,
  timer_getoverrun = 0x104,
  timer_delete = 0x105,
  clock_settime = 0x106,
  clock_gettime = 0x107,
  clock_getres = 0x108,
  clock_nanosleep = 0x109,
  statfs64 = 0x10A,
  fstatfs64 = 0x10B,
  tgkill = 0x10C,
  utimes = 0x10D,
  arm_fadvise64_64 = 0x10E,
  pciconfig_iobase = 0x10F,
  pciconfig_read = 0x110,
  pciconfig_write = 0x111,
  mq_open = 0x112,
  mq_unlink = 0x113,
  mq_timedsend = 0x114,
  mq_timedreceive = 0x115,
  mq_notify = 0x116,
  mq_getsetattr = 0x117,
  waitid = 0x118,
  socket = 0x119,
  bind = 0x11A,
  connect = 0x11B,
  listen = 0x11C,
  accept = 0x11D,
  getsockname = 0x11E,
  getpeername = 0x11F,
  socketpair = 0x120,
  send = 0x121,
  sendto = 0x122,
  recv = 0x123,
  recvfrom = 0x124,
  shutdown = 0x125,
  setsockopt = 0x126,
  getsockopt = 0x127,
  sendmsg = 0x128,
  recvmsg = 0x129,
  semop = 0x12A,
  semget = 0x12B,
  semctl = 0x12C,
  msgsnd = 0x12D,
  msgrcv = 0x12E,
  msgget = 0x12F,
  msgctl = 0x130,
  shmat = 0x131,
  shmdt = 0x132,
  shmget = 0x133,
  shmctl = 0x134,
  add_key = 0x135,
  request_key = 0x136,
  keyctl = 0x137,
  semtimedop = 0x138,
  vserver = 0x139,
  ioprio_set = 0x13A,
  ioprio_get = 0x13B,
  inotify_init = 0x13C,
  inotify_add_watch = 0x13D,
  inotify_rm_watch = 0x13E,
  mbind = 0x13F,
  get_mempolicy = 0x140,
  set_mempolicy = 0x141,
  openat = 0x142,
  mkdirat = 0x143,
  mknodat = 0x144,
  fchownat = 0x145,
  futimesat = 0x146,
  fstatat64 = 0x147,
  unlinkat = 0x148,
  renameat = 0x149,
  linkat = 0x14A,
  symlinkat = 0x14B,
  readlinkat = 0x14C,
  fchmodat = 0x14D,
  faccessat = 0x14E,
  pselect6 = 0x14F,
  ppoll = 0x150,
  unshare = 0x151,
  set_robust_list = 0x152,
  get_robust_list = 0x153,
  splice = 0x154,
  arm_sync_file_range = 0x155,
  sync_file_range2 = 0x155,
  tee = 0x156,
  vmsplice = 0x157,
  move_pages = 0x158,
  getcpu = 0x159,
  epoll_pwait = 0x15A,
  kexec_load = 0x15B,
  utimensat = 0x15C,
  signalfd = 0x15D,
  timerfd_create = 0x15E,
  eventfd = 0x15F,
  fallocate = 0x160,
  timerfd_settime = 0x161,
  timerfd_gettime = 0x162,
  signalfd4 = 0x163,
  eventfd2 = 0x164,
  epoll_create1 = 0x165,
  dup3 = 0x166,
  pipe2 = 0x167,
  inotify_init1 = 0x168,
  preadv = 0x169,
  pwritev = 0x16A,
  rt_tgsigqueueinfo = 0x16B,
  perf_event_open = 0x16C,
  recvmmsg = 0x16D,
  accept4 = 0x16E,
  fanotify_init = 0x16F,
  fanotify_mark = 0x170,
  prlimit64 = 0x171,
  name_to_handle_at = 0x172,
  open_by_handle_at = 0x173,
  clock_adjtime = 0x174,
  syncfs = 0x175,
  sendmmsg = 0x176,
  setns = 0x177,
  process_vm_readv = 0x178,
  process_vm_writev = 0x179,
  kcmp = 0x17A,
  finit_module = 0x17B,
  sched_setattr = 0x17C,
  sched_getattr = 0x17D,
  renameat2 = 0x17E,
  seccomp = 0x17F,
  getrandom = 0x180,
  memfd_create = 0x181,
  bpf = 0x182,
  execveat = 0x183,
  userfaultfd = 0x184,
  membarrier = 0x185,
  mlock2 = 0x186,
  copy_file_range = 0x187,
  preadv2 = 0x188,
  pwritev2 = 0x189,
  pkey_mprotect = 0x18A,
  pkey_alloc = 0x18B,
  pkey_free = 0x18C,
  statx = 0x18D,
  rseq = 0x18E,
  io_pgetevents = 0x18F,
  migrate_pages = 0x190,
  kexec_file_load = 0x191,
  clock_gettime64 = 0x193,
  clock_settime64 = 0x194,
  clock_adjtime64 = 0x195,
  clock_getres_time64 = 0x196,
  clock_nanosleep_time64 = 0x197,
  timer_gettime64 = 0x198,
  timer_settime64 = 0x199,
  timerfd_gettime64 = 0x19A,
  timerfd_settime64 = 0x19B,
  utimensat_time64 = 0x19C,
  pselect6_time64 = 0x19D,
  ppoll_time64 = 0x19E,
  io_pgetevents_time64 = 0x1A0,
  recvmmsg_time64 = 0x1A1,
  mq_timedsend_time64 = 0x1A2,
  mq_timedreceive_time64 = 0x1A3,
  semtimedop_time64 = 0x1A4,
  rt_sigtimedwait_time64 = 0x1A5,
  futex_time64 = 0x1A6,
  sched_rr_get_interval_time64 = 0x1A7,
  pidfd_send_signal = 0x1A8,
  io_uring_setup = 0x1A9,
  io_uring_enter = 0x1AA,
  io_uring_register = 0x1AB,
  open_tree = 0x1AC,
  move_mount = 0x1AD,
  fsopen = 0x1AE,
  fsconfig = 0x1AF,
  fsmount = 0x1B0,
  fspick = 0x1B1,
  pidfd_open = 0x1B2,
  clone3 = 0x1B3,
  close_range = 0x1B4,
  faccessat2 = 0x1B7,
  ARM_breakpoint = 0xF0001,
  ARM_cacheflush = 0xF0002,
  ARM_usr26 = 0xF0003,
  ARM_usr32 = 0xF0004,
  ARM_set_tls = 0xF0005,
  ARM_get_tls = 0xF0006,
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

enum ei_class_2_e : __int8
{      
    ELFCLASSNONE = 0x0,
    ELFCLASS32   = 0x1,
    ELFCLASS64   = 0x2,
    ELFCLASSNUM  = 0x3,
};

enum ei_data_e : __int8
{   
    ELFDATANONE = 0x0,
    ELFDATA2LSB = 0x1,
    ELFDATA2MSB = 0x2,
    ELFDATANUM  = 0x3,
};

enum ei_version_e : __int8
{   
    E_NONE    = 0x0,
    E_CURRENT = 0x1,
    E_NUM     = 0x2,
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

enum e_version32_e
{
  EV_NONE = 0x0,
  EV_CURRENT = 0x1,
};

struct ELFHeader
{
  char magic[4];
  ei_class_2_e ei_class_2;
  ei_data_e ei_data;
  ei_version_e ei_version;
  ei_osabi_e ei_osabi;
  char ei_abiversion;
  char ei_pad[6];
  char ei_nident_SIZE;
  e_type32_e e_type32;
  e_machine32_e e_machine32;
  e_version32_e e_version32;
  char *e_entry_START_ADDRESS;
  char *e_phoff_PROGRAM_HEADER_OFFSET_IN_FILE;
  char *e_shoff_SECTION_HEADER_OFFSET_IN_FILE;
  int e_flags;
  unsigned __int16 e_ehsize_ELF_HEADER_SIZE;
  unsigned __int16 e_phentsize_PROGRAM_HEADER_ENTRY_SIZE_IN_FILE;
  unsigned __int16 e_phnum_NUMBER_OF_PROGRAM_HEADER_ENTRIES;
  unsigned __int16 e_shentsize_SECTION_HEADER_ENTRY_SIZE;
  unsigned __int16 e_shnum_NUMBER_OF_SECTION_HEADER_ENTRIES;
  unsigned __int16 e_shtrndx_STRING_TABLE_INDEX;
};

struct ELFAddressByType
{
  ELF_TYPE type;
  int address;
};

struct readFile
{
    void *buffer;
    int size;
};

struct procParse
{
  char *processStartAddress;
  _DWORD addressRange;
  _DWORD offsetValue;
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

struct procParseArray
{
  void *processStartAddress;
  int addressRange;
  int offsetValue;
  int permFlags;
  int privateOrSharedValue;
  int dev1value;
  int dev2value;
  int inode;
  int fullFilePath;
};
