# `ht_decode` Reverse Engineering

## Overview

This document analyzes the  `lib__57d5__.so` (ELF arm32) lib and it's packed `_ht_decode` function at address `0xC64` inside the `lib__57d5__893216_section_Lv0_type8.bin`, which performs:

1. **AES CBC Decryption** (16-byte blocks)
2. **Huffman RLE Decompression**

## Goal

Replicate the process to decrypt and decompress the file to continue analysis.

## Lib Process Flow

The `lib__57d5__.so` hides its contents within a series of ELF shim "Lv"s. This likely hides anti-debugging and anti-vm code. Each level has a "controller" ELF file and a series of smaller ELF can be compressed, encrypted and / or headerless.

The lib decodes each ELF packed with a PRNG like function before it can be readable.

```c
// Decrypt keyData1
keyData1 = blockStart[8];  // read as int, 32 bytes off from start
start = blockStart;        // starting pointer
len = blockLen;            // length

for (i = 0; i < len; ++i) {
    keyData1 = ((keyData1 * keyData1) >> 11) + 0x1BA379EA;
    *((_BYTE *)start + i) -= keyData1;
}
```

After decoded, the buffer data struture is readable (found in `lib__57d5__masterChunks.bt`).

```c
struct{                            // int index
    uint32 chunkELFStart;          // 0 first chunk, packed in slices that the metaStruct gives start and sizes for
    uint32 chunkELFSize;           // 1 total size of packed chunk
    uint32 chunkELFSliceMetaStart; // 2 Start of meta data on slices within elf chunk
    uint32 chunkELFSliceMetaCount; // 3 number of slices in chunkELF
    uint32 compTableStart;         // 4 (compTableSize != 0) Huffman-coded command stream + RLE decompressor
    uint32 compTableSize;          // 5 Huffman-REL data (decomps when != 0)
    uint32 roundKeysStart;         // 6 (roundKeysSize != 0) AES roundKeys for T-table AES + CBC !FULL_UNROLL https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/crypto/aes.c#1415 
    uint32 roundKeysSize;          // 7 roundKeys size (decrypts when != 0)
    uint32 keyData1;               // 8 area where the encryption key is
    uint32 keyData2;               // 9 area where the encryption key is
    byte gap28[8];                 // 10 gap
    FSeek(chunkELFSliceMetaStart);
    metaELFStruc ELFchunkMeta[chunkELFSliceMetaCount];
    for(local int i<hidden=true> = 0; i < chunkELFSliceMetaCount; i++){
        FSeek(chunkELFStart + ELFchunkMeta[i].srcStart);
        
        metaHolder ELFSlice(ELFchunkMeta[i].srcSize);
    }
    FSeek(chunkELFStart);
    if(compTableSize){
        FSeek(compTableStart);
        byte huffRLEData[compTableSize];
    }    
    if(roundKeysSize){
        FSeek(roundKeysStart);
        keyRoundsBlock keyData(roundKeysSize);
    }
} chunkParse;

typedef struct{
    uint32 srcStart;
    uint32 destStart;
    uint16 srcSize;
    uint16 destSize;
} metaELFStruc;

typedef struct (uint32 size){
    byte ELFSliceData[size];
} metaHolder;

typedef struct (uint32 roundKeysSize){
    uint16 keySizeBits;
    uint16 rounds;
    byte roundKeys[roundKeysSize - 4];
} keyRoundsBlock;
```

If the compiled file doesn't start with ELF magics, it is likely a headerless ELF file with the following headers (found in `lib__57d5__tablesHeaderlessELF.bt`)

```c
typedef struct {
    uint PT_DYNAMIC_OFF; // .dynamic
    uint PT_DYNAMIC_COUNT;
    uint REL_OFF;        // .rel.dyn
    uint REL_COUNT;
    uint JMPREL_OFF;     // .rel.plt
    uint JMPREL_COUNT;
    uint SYMTAB_OFF;     // .dynsym
    uint SYMTAB_COUNT;
    uint STRTAB_OFF;     // .dynstr
    uint STRTAB_COUNT;
    uint SEGMENT_OFF;
    uint SEGMENT_COUNT;
    // data starts at 0x38
} tableELF;
```

The `ht_decode` function is where the process of decompresstion and decrypted happens.

### Main Function: `_ht_decode` at `0xC64`
```
ht_decode:
    ; Check if data needs decrypting
    ; Decrypt 16-byte blocks in place
    ; Decompress using huff RLE
    ; Return decompressed data
```

### Sub-functions:
- **`0xF32`**: Decrypt (inner decryption logic)
- **`0xFF8`**: `AES_decrypt` - AES CBC decryption with T-tables (likely [rijndael-alg-fst](https://fastcrypto.org/front/misc/rijndael-alg-fst.c))
- **`0xD20`**: `huffRLE` - Huffman RLE decompression

Pseudocode:

```c
BOOL __fastcall ht_decode(
        char *DstELFBuffer,
        int DstELFSize,                         // unused (63820 in test case)
        char *DecodedELFStart,
        metaELFStruc *chunkMetaStart,
        int chunkCount,
        int keyLoc1,                            // unused
        decryptionRoundKeys *roundKeys,
        huffRLEBlock *huffTable)
{
  unsigned int srcELFSliceSize; // r5
  char *srcELFSliceStart; // r2
  unsigned int currentOffset; // r3
  unsigned int i; // r3
  char *destStart; // [sp+0h] [bp-402Ch]
  BOOL continueCheck; // [sp+4h] [bp-4028h]
  int currentChunk; // [sp+8h] [bp-4024h]
  int destSize; // [sp+Ch] [bp-4020h]
  ELFSlice ELFSlice; // [sp+18h] [bp-4014h] BYREF
  ELFSlice _tmpELFBuffer; // [sp+20h] [bp-400Ch] BYREF
  _BYTE tmpELFBuffer[16388]; // [sp+28h] [bp-4004h] BYREF

  currentChunk = 0;
  continueCheck = 1;
  // chunkELFSlices
  while ( currentChunk < chunkCount && continueCheck )
  {
    srcELFSliceSize = chunkMetaStart->srcSize;
    srcELFSliceStart = &DecodedELFStart[chunkMetaStart->srcStart];
    destStart = &DstELFBuffer[chunkMetaStart->destStart];
    currentOffset = 0;
    destSize = chunkMetaStart->destSize;
    while ( currentOffset < srcELFSliceSize )
    {
      // copies decoded slice into a tmp buffer
      tmpELFBuffer[currentOffset] = srcELFSliceStart[currentOffset];
      ++currentOffset;
    }
    _tmpELFBuffer.tmpELFSliceOffset = tmpELFBuffer;
    _tmpELFBuffer.srcELFSliceSize = srcELFSliceSize;
    // Checks if 16 byte blocks can be decrypted
    // Leaves remainders
    decrypt(&_tmpELFBuffer, roundKeys);
    // if the src and dest are the same size, it's not compressed
    if ( srcELFSliceSize == destSize )
    {
      for ( i = 0; i < srcELFSliceSize; ++i )
      {
        destStart[i] = tmpELFBuffer[i];
      }
    }
    else
    {
      // tmp is now the dest buffer
      _tmpELFBuffer.tmpELFSliceOffset = destStart;
      _tmpELFBuffer.srcELFSliceSize = destSize;
      // input is now the tmp buffer
      ELFSlice.tmpELFSliceOffset = tmpELFBuffer;
      ELFSlice.srcELFSliceSize = srcELFSliceSize;
      continueCheck = huffRLE(huffTable, &ELFSlice, (DestBuffer *)&_tmpELFBuffer);
    }
    ++chunkMetaStart;
    ++currentChunk;
  }
  return continueCheck;
}

int __fastcall decrypt(ELFSlice *ELFBufferSlice, decryptionRoundKeys *inputRoundKeys)
{
  unsigned int *tmpELFBuffer; // r4
  unsigned int *roundKeys; // r6
  int keySizeBits; // r3
  int rounds; // r3
  int processingFailedFlag; // r5
  unsigned int *currentBuffer; // r7
  unsigned int roundsCheck; // r2
  unsigned int *advancedBuffer; // r5
  unsigned int *tmpSwitch; // r3
  unsigned int srcELFSliceSize; // [sp+0h] [bp-2Ch]
  signed int currentRound; // [sp+0h] [bp-2Ch]
  signed int totalRounds; // [sp+4h] [bp-28h]
  unsigned int inputProcessingBuffer[8]; // [sp+8h] [bp-24h] BYREF

  if ( !ELFBufferSlice )
  {
    return 0;
  }
  tmpELFBuffer = (unsigned int *)ELFBufferSlice->tmpELFSliceOffset;
  srcELFSliceSize = ELFBufferSlice->srcELFSliceSize;
  if ( !inputRoundKeys )
  {
    return 0;
  }
  roundKeys = inputRoundKeys->chunkSubOffset;
  if ( !tmpELFBuffer || !roundKeys )
  {
    return 0;
  }
  // first 2 bytes are the key size in bites
  // Next two are the rounds
  // Key box data is prep set up (AKA no key)
  // Round keys are pushed though AES const with input
  keySizeBits = roundKeys->keyBits;
  if ( keySizeBits == 192 )
  {
    rounds = 12;
    goto LABEL_12;
  }
  if ( keySizeBits != 256 && keySizeBits != 128 )
  {
    return 0;
  }
  if ( keySizeBits == 256 )
  {
    rounds = 14;
  }
  else
  {
    rounds = 10;
  }
LABEL_12:
  processingFailedFlag = 0;
  if ( rounds == roundKeys->rounds )
  {
    currentBuffer = inputProcessingBuffer;
    // zeros out 32 byte buffer
    j_memset(inputProcessingBuffer, 0, sizeof(inputProcessingBuffer));
    roundsCheck = srcELFSliceSize;
    currentRound = 0;
    advancedBuffer = &inputProcessingBuffer[4];
    totalRounds = roundsCheck >> 4;
    while ( currentRound < totalRounds )
    {
      *advancedBuffer = *tmpELFBuffer;          // for CBC
      advancedBuffer[1] = tmpELFBuffer[1];
      advancedBuffer[2] = tmpELFBuffer[2];
      advancedBuffer[3] = tmpELFBuffer[3];
      AES_decrypt(                              // AES decryption round function?
        roundKeys->roundkeys,                   // round keys start
        roundKeys->rounds,                      // rounds
        (unsigned __int8 *)advancedBuffer,      // input
        (unsigned __int8 *)tmpELFBuffer);                          // output
      *tmpELFBuffer ^= *currentBuffer;          // CBC xor
      tmpELFBuffer[1] ^= currentBuffer[1];
      tmpELFBuffer[2] ^= currentBuffer[2];
      tmpELFBuffer[3] ^= currentBuffer[3];
      // advance and switch
      tmpELFBuffer += 4;
      ++currentRound;
      tmpSwitch = currentBuffer;
      currentBuffer = advancedBuffer;
      advancedBuffer = tmpSwitch;
    }
    return 1;
  }
  return processingFailedFlag;
}

void __fastcall AES_decrypt(unsigned int  *rk, int keyLength, unsigned __int8 *input, unsigned __int8 *output)
{
  unsigned int s3; // r5
  unsigned int *_rk; // r4
  unsigned int _rk7; // r7
  unsigned int hbcc; // r6
  unsigned int t3; // r12
  unsigned int *outPtr; // r0
  int o0; // r5
  int o1; // r5
  int o2; // r5
  int o3; // r4
  unsigned int s1; // [sp+8h] [bp-34h]
  unsigned int t1; // [sp+Ch] [bp-30h]
  unsigned int t2; // [sp+10h] [bp-2Ch]
  unsigned int s0; // [sp+14h] [bp-28h]
  unsigned int t0; // [sp+24h] [bp-18h]
  unsigned int s2; // [sp+28h] [bp-14h]
  int r; // [sp+2Ch] [bp-10h]

  r = keyLength >> 1;
  s0 = input[3] ^ *rk ^ (*input << 24) ^ (input[1] << 16) ^ (input[2] << 8);
  s1 = input[7] ^ rk[1] ^ (input[4] << 24) ^ (input[5] << 16) ^ (input[6] << 8);
  s2 = input[11] ^ rk[2] ^ (input[8] << 24) ^ (input[9] << 16) ^ (input[10] << 8);
  s3 = input[15] ^ rk[3] ^ (input[12] << 24) ^ (input[13] << 16) ^ (input[14] << 8);
  for ( _rk = rk;
        ;
        s3 = AES_Td0[HIBYTE(t3)] ^ AES_Td3[(unsigned __int8)t0] ^ _rk[3] ^ AES_Td1[BYTE2(t2)] ^ AES_Td2[BYTE1(t1)] )
  {
    t0 = _rk[4] ^ AES_Td3[(unsigned __int8)s1] ^ AES_Td0[HIBYTE(s0)] ^ AES_Td1[BYTE2(s3)] ^ AES_Td2[BYTE1(s2)];
    t1 = _rk[5] ^ AES_Td3[(unsigned __int8)s2] ^ AES_Td0[HIBYTE(s1)] ^ AES_Td1[BYTE2(s0)] ^ AES_Td2[BYTE1(s3)];
    t2 = _rk[6] ^ AES_Td3[(unsigned __int8)s3] ^ AES_Td0[HIBYTE(s2)] ^ AES_Td1[BYTE2(s1)] ^ AES_Td2[BYTE1(s0)];
    _rk7 = _rk[7];
    _rk += 8;
    hbcc = HIBYTE(t0);
    t3 = AES_Td3[(unsigned __int8)s0] ^ AES_Td0[HIBYTE(s3)] ^ _rk7 ^ AES_Td1[BYTE2(s2)] ^ AES_Td2[BYTE1(s1)];
    if ( !--r )
    {
      break;
    }
    s0 = AES_Td3[(unsigned __int8)t1] ^ AES_Td0[hbcc] ^ *_rk ^ AES_Td1[BYTE2(t3)] ^ AES_Td2[BYTE1(t2)];
    s1 = AES_Td0[HIBYTE(t1)] ^ AES_Td3[(unsigned __int8)t2] ^ _rk[1] ^ AES_Td1[BYTE2(t0)] ^ AES_Td2[BYTE1(t3)];
    s2 = AES_Td0[HIBYTE(t2)] ^ AES_Td3[(unsigned __int8)t3] ^ _rk[2] ^ AES_Td1[BYTE2(t1)] ^ AES_Td2[BYTE1(t0)];
  }
  outPtr = &rk[8 * (keyLength >> 1)];
  o0 = (unsigned __int8)AES_Td4[(unsigned __int8)t1]
     ^ (HIBYTE(AES_Td4[hbcc]) << 24)
     ^ *outPtr
     ^ AES_Td4[BYTE2(t3)]
     & 0xFF0000
     ^ AES_Td4[BYTE1(t2)]
     & 0xFF00;
  *output = HIBYTE(o0);
  output[1] = BYTE2(o0);
  output[2] = BYTE1(o0);
  output[3] = o0;
  o1 = outPtr[1]
     ^ (unsigned __int8)AES_Td4[(unsigned __int8)t2]
     ^ (HIBYTE(AES_Td4[HIBYTE(t1)]) << 24)
     ^ AES_Td4[BYTE2(t0)]
     & 0xFF0000
     ^ AES_Td4[BYTE1(t3)]
     & 0xFF00;
  output[4] = HIBYTE(o1);
  output[5] = BYTE2(o1);
  output[6] = BYTE1(o1);
  output[7] = o1;
  o2 = outPtr[2]
     ^ (unsigned __int8)AES_Td4[(unsigned __int8)t3]
     ^ (HIBYTE(AES_Td4[HIBYTE(t2)]) << 24)
     ^ AES_Td4[BYTE2(t1)]
     & 0xFF0000
     ^ AES_Td4[BYTE1(t0)]
     & 0xFF00;
  output[8] = HIBYTE(o2);
  output[9] = BYTE2(o2);
  output[10] = BYTE1(o2);
  output[11] = o2;
  o3 = AES_Td4[BYTE1(t1)]
     & 0xFF00
     ^ AES_Td4[BYTE2(t2)]
     & 0xFF0000
     ^ (unsigned __int8)AES_Td4[(unsigned __int8)t0]
     ^ (HIBYTE(AES_Td4[HIBYTE(t3)]) << 24)
     ^ outPtr[3];
  output[12] = HIBYTE(o3);
  output[13] = BYTE2(o3);
  output[14] = BYTE1(o3);
  output[15] = o3;
}

BOOL __fastcall huffRLE(huffRLEBlock *huffTable, ELFSlice *elfSliceInfo, DestBuffer *destinationStart)
{
  int adjustedAmount; // r12
  char *out_buf; // r0
  int compressionLevel; // r7
  int repeatAmount; // r3
  int firstRead; // r1
  unsigned __int8 *adjustedChunkOffset; // r5
  unsigned int subChunkRead1; // r6
  int subChunkRead2; // r4
  int subChunkRead0; // r5
  int v13; // r2
  __int16 stride; // r5
  int v15; // r5
  int i; // r6
  unsigned __int8 *currentNode; // r6
  unsigned int nextNode; // r5
  int v19; // r2
  int op; // r2
  int counter1; // r2
  char *out_buf2; // r2
  int counter2; // r1
  char *_out_buf4; // r2
  int counter4; // r1
  int v26; // r3
  char *inverse; // r3
  int j; // r2
  char *in_buf; // [sp+4h] [bp-30h]
  int index; // [sp+8h] [bp-2Ch]
  int out_len; // [sp+Ch] [bp-28h]
  int sizeRead; // [sp+10h] [bp-24h]
  unsigned __int8 *nodes; // [sp+18h] [bp-1Ch]
  int in_len; // [sp+1Ch] [bp-18h]
  int i2; // [sp+20h] [bp-14h]

  nodes = huffTable->compTable;
  out_buf = destinationStart->destOffset;
  in_buf = elfSliceInfo->tmpELFSliceOffset;
  in_len = elfSliceInfo->srcELFSliceSize;
  out_len = destinationStart->dstSize;
  if ( !nodes || !in_buf || !out_buf || !in_len || !out_len )
  {
    return 0;
  }
  compressionLevel = 0;
  sizeRead = 0;
  repeatAmount = 0;
  for ( index = 0; index < out_len; index += adjustedAmount )
  {
    if ( sizeRead >= in_len )
    {
      return 0;
    }
    firstRead = *(_DWORD *)in_buf;
    if ( compressionLevel )
    {
      firstRead = *(_DWORD *)in_buf >> compressionLevel;
    }
    adjustedChunkOffset = &nodes[3 * (unsigned __int8)firstRead];
    subChunkRead1 = adjustedChunkOffset[1];
    subChunkRead2 = adjustedChunkOffset[2];
    subChunkRead0 = *adjustedChunkOffset;
    if ( subChunkRead1 >> 7 )
    {
      v13 = subChunkRead2;
      stride = subChunkRead0 | ((subChunkRead1 & 0x7F) << 8);
    }
    else
    {
      v13 = subChunkRead2 + 1;
      v15 = subChunkRead0 | ((subChunkRead1 & 0x7F) << 8);
      for ( i = 1 << subChunkRead2; ; i = 2 * i2 )
      {
        i2 = i;
        currentNode = &nodes[3 * v15 + 3 * ((i & firstRead) != 0)];
        nextNode = currentNode[1];
        if ( nextNode >> 7 )
        {
          break;
        }
        v15 = ((nextNode & 0x7F) << 8) | *currentNode;
        ++v13;
      }
      stride = ((nextNode & 0x7F) << 8) | *currentNode;
    }
    v19 = compressionLevel + v13;
    compressionLevel = v19 & 7;
    in_buf += v19 >> 3;
    sizeRead += v19 >> 3;
    op = stride & 0x300;
    if ( (stride & 0x300) == 0 )
    {
      *out_buf = stride;
      adjustedAmount = 1;
      goto LABEL_50;
    }
    if ( op == 0x100 )
    {
      if ( repeatAmount > 0xFF )
      {
        return 0;
      }
      if ( repeatAmount )
      {
        repeatAmount = (repeatAmount << 8) | (unsigned __int8)stride;
      }
      else
      {
        repeatAmount = (unsigned __int8)stride;
      }
      adjustedAmount = 0;
    }
    else
    {
      if ( op == 0x200 )
      {
        if ( !repeatAmount )
        {
          repeatAmount = 1;
        }
        adjustedAmount = repeatAmount * (unsigned __int8)stride;
        if ( index + adjustedAmount > out_len )
        {
          return 0;
        }
        switch ( (unsigned __int8)stride )
        {
          case 1u:
            counter1 = 0;
            do
            {
              out_buf[counter1++] = *(out_buf - 1);
            }
            while ( counter1 < repeatAmount );
            break;
          case 2u:
            out_buf2 = out_buf;
            counter2 = 0;
            do
            {
              ++counter2;
              *out_buf2 = *(out_buf - 2);
              out_buf2[1] = *(out_buf - 1);
              out_buf2 += 2;
            }
            while ( counter2 < repeatAmount );
            break;
          case 4u:
            _out_buf4 = out_buf;
            counter4 = 0;
            do
            {
              ++counter4;
              *_out_buf4 = *(out_buf - 4);
              _out_buf4[1] = *(out_buf - 3);
              _out_buf4[2] = *(out_buf - 2);
              _out_buf4[3] = *(out_buf - 1);
              _out_buf4 += 4;
            }
            while ( counter4 < repeatAmount );
            break;
        }
      }
      else
      {
        if ( op != 0x300 )
        {
          goto LABEL_50;
        }
        adjustedAmount = (unsigned __int8)stride;
        if ( index + (unsigned __int8)stride > out_len )
        {
          return 0;
        }
        v26 = repeatAmount + (unsigned __int8)stride;
        if ( index < v26 )
        {
          return 0;
        }
        inverse = &out_buf[-v26];
        for ( j = 0; j < (unsigned __int8)stride; ++j )
        {
          out_buf[j] = inverse[j];
        }
      }
      repeatAmount = 0;
    }
LABEL_50:
    out_buf += adjustedAmount;
  }
  return sizeRead + (compressionLevel != 0) == in_len;
}
```

## Binary Template Structure

Test case `lib__57d5__68112_section_Lv1_type144_encrypted.bin` can be read with `lib__57d5__masterChunks.bt` (extracts to 63820 byte buffer). 

This file has already been decoded from the PRNG function.

## AES CBC Decryption Details

### Function at `0xFF8` - `AES_decrypt`:
- Uses pre-built AES T-tables (unrolled)
- CBC mode with IV (blank 0x00 filled buffer)
- Decrypts 16-byte blocks
- Reference: Likely [Android QEMU AES implementation](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/crypto/aes.c#1415)

### Function at `0xF32` - `Decrypt`:
- Inner decryption logic
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

## Next Steps

- Created `test_extract.js` for node.
- Was able to recreate PRNG function but wasn't successful after that.
- Will likely need changes from the source pseudocode to work.
- Different programming language could be easier.
