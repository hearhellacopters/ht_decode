# `ht_decode` Reverse Engineering

The `ht_decode` protection system removes or transforms significant portions of the original ELF metadata and executable image, then reconstructs the library at runtime through a custom loader. The goal of this repository is to follow that reconstruction process, document the format and algorithms involved, and recreate a research-oriented representation of the original library for static analysis.

This project does **not** remove the protection from an application, produce a modified APK, or generate a drop-in replacement library suitable for deployment. Instead, it recreates the library and associated metadata in a form that can be examined using reverse engineering tools such as IDA Pro and Ghidra.

The name `ht_decode` comes from several components found in an older (referred to here as "Legacy") version of the protection system, including libraries with such names as:

* `libht_decode`
* `libht_reloc_ndk`
* `libht_mutex`

While `ht` likely refers to **"hash table"** (but has nothing to do with an ELF hash table), it could also be an internal component or subsystem used by the vendor, its exact meaning remains unknown.

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

## Overview

*Note: The non "Legacy" version of this software has different strutures, decoding functions and more libs genereated doing more checks, but the basic concept is the same. You can find research in my [ida pro project](/ida/), [binrary templates](/bt/), stucts.h and Structures.js (as well as 32 vs 64 bit) files for details on how the process works. This is just a basic overview into my findings.*

This document analyzed the  `lib__57d5__.so` (ELF arm32) lib and it's packed `_ht_decode` function which performs:

1. **AES CBC Dencryption** (16-byte blocks)
2. **Huffman RLE Decompression** (3 byte)

## Lib Process Flow

The `lib__57d5__.so` hides its contents within a series of ELF shim "Lv"s. This is where it hides its anti-debugging and anti-vm code. Each level has a "controller" ELF file and a series of smaller ELFs that can be compressed, encrypted and / or headerless. The lib decodes each ELF packed with a PRNG like function before it can be readable. After decoded, the buffer data struture is readable.

If the compiled file doesn't start with ELF magics, it is likely a headerless ELF file with the following headers (found in `lib__57d5__tablesHeaderlessELF.bt`)

The `ht_decode` function is where the process of decompression and dencryption happens.

### Main Function: `_ht_decode` at `0xC64`
```
ht_decode:
    ; Check if data needs decrypting
    ; Decrypt 16-byte blocks in place
    ; Decompress using huff RLE
    ; Return decompressed data
```

### Sub-functions:
- **`0xF32`**: Decrypt (inner dencryption logic)
- **`0xFF8`**: `AES_decrypt` - AES CBC dencryption with T-tables (likely [rijndael-alg-fst](https://fastcrypto.org/front/misc/rijndael-alg-fst.c))
- **`0xD20`**: `huffRLE` - Huffman RLE decompression

## Binary Template Structure

Test case `lib__57d5__68112_section_Lv1_type144_encrypted.bin` can be read with `lib__57d5__masterChunks.bt` (extracts to 63820 byte buffer). 

This file has already been decoded from the PRNG function.

## AES CBC Dencryption Details

### Function at `0xFF8` - `AES_decrypt`:
- Uses pre-built AES T-tables (unrolled)
- CBC mode with IV (blank 0x00 filled buffer)
- Decrypts 16-byte blocks
- Reference: Likely [Android QEMU AES implementation](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/crypto/aes.c#1415)

### Function at `0xF32` - `Decrypt`:
- Inner dencryption logic
- Likely XOR with previous ciphertext block (CBC)
- Calls `AES_decrypt` for each block

## Huffman RLE Decompression (0xD20)

### Function at `0xD20` - `huffRLE`:
- Uses pre-built Huffman-coded command stream
- RLE (Run-Length Encoding) decompression
- Can handle repeating numbers
- Reads from `compTable`

## Implementation Plan

### 1. AES Decrypt
- IV (Initialization Vector)
- Block size: 16 bytes
- Replicate key round function

### 2. Huffman RLE Table
- Extract command stream from `compTable`
- RLE table for decompression

## Test Case Requirements

- **Destination buffer size**: 63820 bytes
- **Input**: `lib__57d5__68112_section_Lv1_type144_encrypted.bin`
- **Output**: Headerless ELF file (loadable with `custom_android_loader.py` in IDA Pro)

## Lib Process Flow

- The whole system is dynamically linked without the use of many external libs.
- Headerless ELFs are used to hide process (`custom_android_loader32.py` or `lib__57d5__tablesHeaderlessELF.bt` to read them)
- Each "Lv" has a nameless control ELF that will unpack other "table" ELF libs that act as shims.

### Flow

Most of these libs have a function that the "Lv" runs when first decoded.

Lv0 ELF ->
- 5 = Lib list (nameless but calling it `dllidlist.so`)
- 4 = setupDT_NEEDED (nameless but calling it `setupDT_NEEDED.so`)
- 1 = setHtElfTab(ble), HtLoadLibrary, HtGetProcAddress (nameless but calling it `dthelper.so`)
- 2 = ht_lookup, ht_gnu_lookup (nameless but calling it `ht_lookup_lite.so`)
- 3 = ht_lookup, ht_gnu_lookup, __aeabi_uidiv, __aeabi_uidivmod (nameless but calling it `ht_lookup.so`)
- 6 = `libht_reloc_ndk.so` (also setHtElfTab(ble), HtLoadLibrary, HtGetProcAddress)
- 8 = `libht_decode.so` (ht_decode)
- 9 = `libht_mutex.so` (lockMutex unlockMutex)

Lv1 ELF ->
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

Lv2 ELF ->
- 248 = `data248.bin` (No a lib. This data gets decoded again and applied directly to the master lib)
- 241 = `data241.bin` (No a lib. The symbol and string table to be added back to the master lib)
- 242 = DT tables with no code (nameless but calling it `lib242.so`)
- 240 = `libLvDecode.so`

## Additional Research

It was found that later the libs use the section table offset from `SHT_LOUSER` to store the data, not hard offsets for the table reads.

Added additional check at the start for `SHT_LOUSER` section for offsetting.