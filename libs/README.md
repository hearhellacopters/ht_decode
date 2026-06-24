# `ht_decode` Reverse Engineering

The `ht_decode` protection system removes or transforms significant portions of the original ELF metadata and executable image, then reconstructs the library at runtime through a custom loader. The goal of this repository is to follow that reconstruction process, document the format and algorithms involved, and recreate a research-oriented representation of the original library for static analysis.

This project does **not** remove the protection from an application, produce a modified APK, or generate a drop-in replacement library suitable for deployment. Instead, it recreates the library and associated metadata in a form that can be examined using reverse engineering tools such as IDA Pro and Ghidra.

The name `ht_decode` comes from several components found in an older (referred to here as "Legacy") version of the protection system, including libraries with such names as:

* `libht_decode`
* `libht_reloc_ndk`
* `libht_mutex`

## Project Goals

The primary goals of this repository is to:

* Document the protected library format.
* Reverse engineer the runtime reconstruction process.
* Recreate stripped ELF metadata used by the Android dynamic linker.
* Recover relocation and symbol information useful for static analysis.
* Generate auxiliary data such as IDA Pro renaming scripts.
* Preserve research findings in a reproducible and documented form.

## What the Protection System Does

At a high level, the protection system transforms a native ELF shared object into a compact protected representation.

During application startup, a custom loader performs a series of operations such as:

1. Loading the protected library image.
2. Preforming various hash checks as well as checks for VMs, debugging and specific package names.
3. Reconstructing portions of the original ELF layout.
4. Rebuilding dynamic linker metadata.
5. Restoring relocation information.
6. Resolving imported symbols.
7. Transferring execution to the reconstructed library.

A key observation is that some ELF metadata is not stored directly in the reconstructed library. Instead, it exists in auxiliary structures ("sidecar" data) used during the reconstruction process. These structures contain information such as:

* Dynamic linker tables.
* String tables.
* Symbol tables.
* Relocation tables.
* Procedure linkage metadata.

## Identifying

While there might be other names used, identifying this type of packer can normally be found in APKs packed with a `lib__57d5__.so` library as well as the application's meain library (but it may use other names). This unpacker is used on both the `lib__57d5__.so` file and the main library (so all checks are run twice). 

Another easy way to identify this unpacker is by it's odd choice to use the `com.google.android.gms.common.api.GoogleApiActivitya` class for it's callbacks in the APK's dex file.

```java
static {
  System.loadLibrary("__57d5__");
  A = GoogleApiActivitya.a(1828815997);
  B = GoogleApiActivitya.a(1215689502);
  C = GoogleApiActivitya.a(-1843249638);
  D = GoogleApiActivitya.a(1246347914);
  // etc
}
```

## Overview

*Note: The non "Legacy" version of this software has different strutures, decoding functions and more libs genereated doing more checks, but the basic concept is the same. You can find research in my [ida pro project](/ida/), [010 binary templates](/bt/), stucts.h and Structures.js (as well as 32 vs 64 bit) files for details on how the process works. This is just a basic overview into my findings.*

This document analyzed the  `lib__57d5__.so` (ELF arm32) lib and it's packed `_ht_decode` function which performs:

1. **AES CBC Decryption** (16-byte blocks)
2. **Huffman RLE Decompression** (3 byte)

## Lib Process Flow

The `lib__57d5__.so` hides its contents within a series of ELF shim "Lv"s. This is where it hides its anti-debugging and anti-vm code. Each level has a "controller" ELF file and a series of smaller ELFs that can be compressed, encrypted and / or headerless. The lib decodes each ELF packed with a PRNG like function before it can be readable. After decoded, the buffer data structure is readable.

If the compiled file doesn't start with ELF magics, it is likely a headerless ELF file.

The `ht_decode` function is where the process of decompression and decryption happens.

 - Check if data needs decrypting
   - AES CBC decryption with T-tables (likely [rijndael-alg-fst](https://fastcrypto.org/front/misc/rijndael-alg-fst.c))
 - Decompress using huff RLE
 - Returns decompressed data

The Legacy version has an AES table attached per compressed library, while the more recent ones use an AES table hardcoded to the library that decrypts all libraries in that "level".

- The whole system is dynamically linked without the use of many external libs.
- Headerless ELFs are used to hide process (`custom_android_loader##.py` or [010 binary templates](/bt/) to read them)
- Each "Lv" has a nameless control ELF that will unpack other "table" ELF libs that act as shims.

### Flow

Most of these libraries have a "passoff" function that the master "Lv" runs when first decoded. The unpacker gives each library a number to recall later for use. These are the observed layouts and uses.

#### Legacy

Lv0 ELFs ->
- 5 = Lib list (nameless but calling it `dllidlist.so`)
- 4 = setupDT_NEEDED (nameless but calling it `setupDT_NEEDED.so`)
- 1 = setHtElfTab(ble), HtLoadLibrary, HtGetProcAddress (nameless but calling it `dthelper.so`)
- 2 = ht_lookup, ht_gnu_lookup (nameless but calling it `ht_lookup_lite.so`)
- 3 = ht_lookup, ht_gnu_lookup, __aeabi_uidiv, __aeabi_uidivmod (nameless but calling it `ht_lookup.so`)
- 6 = `libht_reloc_ndk.so` (also setHtElfTab(ble), HtLoadLibrary, HtGetProcAddress)
- 8 = `libht_decode.so` (ht_decode)
- 9 = `libht_mutex.so` (lockMutex unlockMutex)

Lv1 ELFs ->
- 144 = `libtest.so`
- 16  = `liboptapkchk.so`
- 18  = `liboptcertchk.so`
- 19  = `liboptcoredumpgrd.so`
- 20  = `liboptdalvikchk.so`
- 21  = `liboptddmsgrd.so`
- 22  = `liboptdebuggrd.so`
- 23  = `liboptdexchk.so`
- 24  = `liboptemuchk.so`
- 26  = `liboptloadpathchk.so`
- 27  = `liboptnotifylog.so`
- 28  = `liboptodexchk.so`
- 29  = `liboptprotectmem.so`
- 146 = `data146.bin` (No a lib. "CP Data" used in libtest and likely others)
- 145 = `libOptCommonExec.so`

Lv2 ELFs ->
- 248 = `data248.bin` (No a lib. This data gets decoded again and applied directly to the master lib)
- 241 = `data241.bin` (No a lib. The symbol and string table to be added back to the master lib)
- 242 = DT tables with no code (nameless but calling it `lib242.so`)
- 240 = `libLvDecode.so`

#### Non-Legacy

*Note: Later version of this unpacker removed all strings and function names so the nemerical value of each library is used with a description of what they do. There is also a sidecar file commonly called "data1.dat" that has other data including libraries. Due to the configurable nature of the unpacker, other libaraies might be missing as they weren't used in my test cases. Everything found was included here for reference.*

Non Lv ->
- 225 = The raw loaded master library
- 208 = The read write load section of the master library
- 154 = File reader (not a real library but used as reference to a subroutine)
- 4   = A dex hash list found inside data1.dat
- 5   = A library hash list found inside data1.dat
- 7   = An asset hash list found inside data1.dat
- 8   = The AndroidManifest.xml loaded from inside data1.dat
- 128 = Found inside data1.dat (Intel 386 version of 129)
- 136 = Found inside data1.dat (Intel 386 version of 137)
- 137 = Found inside data1.dat (Arm32)
- 132 = Found inside data1.dat (x86_64)
- 133 = Found inside data1.dat (Arm64)
- 226 = `libLv0.so`

Lv0 ELFs ->
- 129 = Basic C functions for this level 
  - A 129 is also found inside data1.dat but doesn't look the same
- 150 = Shim functions and cross references
- 243 = Raw data to be used to decode next level
- 227 = `libLv1.so`

Lv1 ELFs ->
- 143 = Heavy file lifing and pass off stuff
- 151 = Device checks and builds email
- 142 = Creates `__57d5__.log` and sends emails
- 244 = Raw data to be used to decode next level
- 228 = `libLv2.so`,

Lv2 ELFs ->
- 2   = Basic C functions for this level
- 106 = Found blank but referenced as a list of package names to check for
- 105 = Checks for super user, magisk and others package names
- 96  = Checks for vm
- 64  = Calls `data1.dat` to check assets and manifest
- 32  = Calls `data1.dat` to check library
- 84 =  Checks phone model
- 51 =  Calls `data1.dat` to check dex files
- 245 = Raw data to be used to decode next level
- 229 = `libLv3.so`

Lv3 ELFs ->
- 83  = Process management (Has two more packed libraries (both ELF for Intel 386))
- 164 = Thread management
- 88  = calls `data1.dat` to decode 128, 129, 136, 137 
- 246 = Raw data to be used to decode next level
- 230 = `libLv4.so`

Lv4 ELFs ->
- 3   = Basic C functions for this level
- 160 = Reruns some libraries with a different pass off config
- 247 = Raw data to be used to decode next level
- 231 = `libLv5.so`

Lv5 & Lv6 ELFs ->
- 178 = Rel / JmpRel linking table
- 176 = Shell C lib for basic mem and str funcitions
- 185 = Addresses for locations to copy memset / strcat / chr / cmp / cpy / len address to other libraries from Lv6
- 157 = Raw data used to recreate master library
- 158 = dynamic symbols & strings table
- 194 = chunk data needing offets in Lv6 (only in 32 bit libs)
- 195 = jump bytecode needing offsets re-written (only in 32 bit libs)
- 155 = `libLv6.so` the library that recreates the master
- 248 = Raw data to be used to decode next level
- 232 = `libLv7.so`

Lv7 ELFs ->
- 152 = `libLv8.so`

## Additional Notes

Library 155 (Lv6) is the library that builds the master.

Order of Operations ->
 - Library 158 - Copies dynsym dynstr sections to master library
 - Data 157 - Decoded and adds programming table that overrides the master (just the first offset)
 - The headers offset in 157 is a sidecar dynamic table that has other symbols striped from the master library (parsed as a python script for renaming)
 - Data 178 are cross references to match 157 headers for shim functions indexes
 - Data 185 copies offset to direct C functions (memset, strcpy etc) pulled from Lv6
 - Data 195 is a cross jump of offsets to data 194 and the master library for function jumping to hide where the real function is (it's normally just after the location of the first jump in the master)
