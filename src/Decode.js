// @ts-check

const { FS } = require('./File');
const {
    readMasterChunk,
    createMasterTable,
    readSubTable,
    readData1Entries
} = require('./Structures');
const { decryptSlice } = require('./Decryption');
const {
    readDecompHeader,
    decompressSlice
} = require('./Decompress')

// #region Legacy

/**
 * Runs the PRNG operation on Buffer
 * 
 * @example 
 * ```js
 * PRNG(buffer, buffer.byteLength, buffer.readUint32LE(32))
 * ```
 * @param {Buffer} buffer input buffer
 * @param {number} length length of the buffer
 * @param {number} key found 32 bytes after start
 */
function PRNG(buffer, length, key) {
    let state = key;

    for (let i = 0; i < length; i++) {
        // PRNG state: state = ((state * state) >> 11) + 0x1BA379EA   (all uint32 arithmetic)
        const bigState = BigInt(state);

        const squared = (bigState * bigState) & 0xFFFFFFFFn;        // multiply mod 2³²

        const shifted = squared >> 11n;                             // >> 11 on the 32-bit result

        state = Number((shifted + 0x1BA379EAn) & 0xFFFFFFFFn);      // add constant, keep uint32
        // Subtract from current byte (exactly as *((_BYTE*)start + i) -= keyData1)
        // Because destination is a byte, this is always mod 256
        buffer[i] = (buffer[i] - (state & 0xFF)) & 0xFF;
    }
};

/**
 * Decode a string from a buffer
 * 
 * @example
 * ```js
 * const array = new Uint32Array([0x12F212D2, 0xF61351D3, 0x5332]);
 * 
 * const buffer =  Buffer.from(array.buffer, array.byteOffset, array.byteLength);
 * 
 * const decodedStr = DoDecodeString(buffer);
 * ```
 * 
 * @param {Buffer} buffer 
 * @returns 
 */
function DoDecodeString(buffer) {
    let i;
    for (i = 0; i < buffer.length && buffer[i] !== 0; i++) {
        buffer[i] = (~((8 * buffer[i]) | (buffer[i] >> 5)) - (i & 3)) & 0xFF;
    }
    return buffer.subarray(0, i).toString();
};

/**
 * Create elf from PRNG and sliced chunks
 * 
 * @param {Buffer} ElfChunk 
 * @param {Buffer<ArrayBufferLike> | undefined} MASTER_ELF_BUFFER 
 */
function decodeELF(ElfChunk, MASTER_ELF_BUFFER = undefined) {
    PRNG(ElfChunk, ElfChunk.byteLength, ElfChunk.readUint32LE(32));

    const chunkData = readMasterChunk(ElfChunk);

    let totalDestSize = 0;

    if (MASTER_ELF_BUFFER == undefined) {
        for (let i = 0; i < chunkData.metas.length; i++) {
            const m = chunkData.metas[i];

            totalDestSize = Math.max(totalDestSize, m.destStart + m.destSize);
        }

        MASTER_ELF_BUFFER = Buffer.alloc(totalDestSize);
    }

    const huffData = chunkData.compTableSize > 0 ? ElfChunk.subarray(chunkData.compTableStart, chunkData.compTableStart + chunkData.compTableSize) : null;

    const sboxData = chunkData.roundKeysSize > 0 ? ElfChunk.subarray(chunkData.roundKeysStart, chunkData.roundKeysStart + chunkData.roundKeysSize) : null;
    // copy buffer
    if (huffData == null && sboxData == null) {
        for (let i = 0; i < chunkData.metas.length; i++) {
            const m = chunkData.metas[i];

            const copyBuffer = ElfChunk.subarray(chunkData.chunkELFStart + m.srcStart, chunkData.chunkELFStart + m.srcStart + m.srcSize);

            MASTER_ELF_BUFFER.set(copyBuffer.subarray(0, m.destSize), m.destStart);
        }
    } else {
        // decrypt / decompress
        for (let i = 0; i < chunkData.metas.length; i++) {
            const m = chunkData.metas[i];

            const srcData = ElfChunk.subarray(
                chunkData.chunkELFStart + m.srcStart,
                chunkData.chunkELFStart + m.srcStart + m.srcSize
            );

            if (sboxData != null) {
                if (!decryptSlice(srcData, sboxData)) {
                    FS.hexdump(srcData);

                    console.log(`[!] Error: AES failed on slice ${i}.`);

                    process.exit(0);
                }
            }
            // Write to final ELF
            if (m.srcSize === m.destSize) {
                srcData.copy(MASTER_ELF_BUFFER, m.destStart, 0, m.destSize);
            } else {
                const tmpBuffer = Buffer.alloc(Math.max(m.srcSize, 32));

                srcData.copy(tmpBuffer, 0, 0, m.srcSize);

                const dest = MASTER_ELF_BUFFER.subarray(m.destStart, m.destStart + m.destSize);

                if (huffData != null) {
                    if (!decompressSlice(huffData, tmpBuffer, m.srcSize, dest)) {
                        FS.hexdump(tmpBuffer);

                        console.log(`[!] Error: Decompress failed on slice ${i}.`);

                        process.exit(0);
                    }
                }
            }
        }
    }

    return MASTER_ELF_BUFFER;
};

// #region 64 bit and on

/**
 * hack for 64bit processors
 * 
 * @param {number} a 
 * @param {number} b 
 */
function multiplyInt(a, b) {
    const result = BigInt(a) * BigInt(b);
    return Number(result & BigInt('0xffffffff'));
};

/**
 * Runs the a PRNG operation on Buffer
 * 
 * @param {number} seed 
 * @param {Buffer} buffer 
 * @param {number} len 
 * @param {number} start 
 */
function PRNG_MASTER(seed, buffer, len, start) {
    const words = new Uint32Array(buffer.buffer, buffer.byteOffset, len >> 2);

    for (let i = start >> 2; i < len >> 2; ++i) {
        words[i] += (i + 3) * seed;
        words[i] ^= 0xBF20165D * (i + 1);
    }
};

/**
 * Runs the PRNG operation on Buffer
 * 
 * @param {Buffer} buffer
 * @param {number} size 
 * @param {number} seed 
 */
function PRNG_SLICE(buffer, size, seed = 0x745F) {
    let xor1 = 0x7B48238;

    let xor2 = 0xE34EAC63;

    seed >>>= 0;

    for (let i = 0; i < (size >> 2); ++i) {
        let term1 = multiplyInt(xor1, xor1 - 0x1605A81C);

        let sum1 = (term1 + seed - 0x71B6A98D) >>> 0;

        xor1 = (sum1 << (i & 7)) >>> 0;

        let term2 = multiplyInt(xor2, xor2 + 0x4F8B1BCA);

        let sum2 = (term2 + seed + 0x72F6FCBE) >>> 0;

        xor2 = sum2 >>> ((i * i) & 0xF);

        seed = (xor2 ^ xor1) >>> 0;

        let val = buffer.readUInt32LE(4 * i);

        val = (val - multiplyInt(0x4BC46451, i & 0xD)) >>> 0;

        val ^= multiplyInt(0xAF57F7FB, i & 3);

        val >>>= 0;

        val = (val - (xor2 ^ xor1)) >>> 0;

        val ^= (xor2 ^ xor1);

        val >>>= 0;

        buffer.writeUInt32LE(val, 4 * i);
    }
};

/**
 * Decodes a 32 btye table (normally 572 bytes off the start of 
 * 
 * @param {Buffer} buffer 
 */
function DecodeMasterTable(buffer) {
    const seed = buffer.readUint32LE(0);

    PRNG_MASTER(seed, buffer, 32, 0);

    buffer.writeUint32LE(seed, 0);

    return createMasterTable(buffer);
};

/**
 * Creates XOR value
 * 
 * @param {number} input 
 * @param {number} seed
 */
function makeXor(input, seed = 0x94511DD2) {
    let returnValue = 0;

    while (seed !== 0) {

        if ((seed & 1) !== 0) {
            returnValue ^= input;
        }

        const isInputNegative = (input & 0x80000000) !== 0;

        input <<= 1;

        if (isInputNegative) {
            input ^= 0x579357EB;
        }

        seed >>>= 1;
    }

    return returnValue >>> 0;
};

/**
 * Returns both quotient and remainder (like divmod)
 * 
 * @param {number} dividend
 * @param {number} divisor
 * @returns {{quotient: number, remainder: number}}
 */
function divmod(dividend, divisor) {
    if (divisor === 0) {
        throw new Error("Floating point exception (division by zero)");
    }

    const quotient = Math.trunc(dividend / divisor);

    const remainder = dividend - divisor * quotient;

    return { quotient, remainder };
};

/**
 * Returns both quotient and remainder (like udivmod)
 * 
 * @param {number} dividend
 * @param {number} divisor
 * @returns {{quotient: number, remainder: number}}
 */
function udivmod(dividend, divisor) {
    dividend = dividend >>> 0;

    divisor = divisor >>> 0;

    if (divisor === 0) {
        throw new Error("Floating point exception (division by zero)");
    }

    const quotient = Math.floor(dividend / divisor);

    const remainder = dividend - divisor * quotient;

    return { quotient, remainder };
};

/**
 * ror32 - 32-bit Rotate Right (equivalent to __ROR4__ in IDA)
 * 
 * @param {number} value
 * @param {number} shift
 */
function ror32(value, shift) {
    value = value >>> 0;
    shift = shift & 0x1F;                    // modulo 32
    return (value >>> shift) | (value << (32 - shift)) >>> 0;
};

const Type3ByteOffset1 = Buffer.from([
    1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
    2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0,
    0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
    3, 3, 3, 0, 3, 3, 3, 3, 3, 0, 0, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 3, 3,
    3, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 2, 0,
    4, 4, 5, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 5, 5, 5, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4,
    1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
    2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0,
    0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
    3, 3, 3, 0, 3, 3, 3, 3, 3, 0, 0, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 2, 0,
    4, 4, 5, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 5, 5, 5, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4,
]);

const Type3ByteOffset2 = Buffer.from([
    1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1
]);

/**
 * type0 hash check
 * 
 * @param {Buffer} buffer
 * @param {number} size 
 * @param {number} offset 
 */
function hashDevType0(buffer, size, offset) {
    let end = (size + offset) >>> 0;

    let div7rem = udivmod(offset, 7).remainder;

    let div11rem = udivmod(offset, 11).remainder;

    let div13rem = udivmod(offset, 13).remainder;

    let counter = 0;

    while (counter !== size) {
        const valueRead = buffer[counter] & 0xFF;

        let mod1 = (end + 0x448B0D21 + valueRead) >>> 0;

        let mod2 = (valueRead + counter) >>> 0;

        let mod3 = (mod1 - multiplyInt(0x76F07E8E, mod2)) >>> 0;

        const ror7 = ror32(mod3, div7rem);

        const ror11 = ror32(mod3, div11rem);

        const ror13 = ror32(mod3, div13rem);

        let mod4 = (ror7 + ror11) >>> 0;

        div7rem = (div7rem === 6) ? 0 : div7rem + 1;

        div13rem = (div13rem === 12) ? 0 : div13rem + 1;

        div11rem = (div11rem === 10) ? 0 : div11rem + 1;

        end = (mod4 + mod3 + ror13) >>> 0;

        counter++;
    }

    return end;
};

/**
 * type1 hash check
 * 
 * @param {Buffer} buffer buffer is 112 bytes
 * @param {number} size 
 * @param {number} offset 
 */
function hashDevType1(buffer, size, offset) {
    buffer.writeUint32LE(0, 8);

    return hashDevType0(buffer, size, offset);
};

/**
 * type2 hash check
 * 
 * @param {Buffer} buffer
 * @param {number} size 
 * @param {number} offset 
 */
function hashDevType2(buffer, size, offset) {
    let end = (size + offset) >>> 0;

    const chunksOf32 = size >>> 5;        // size / 32

    let p_buffer_index = 0;

    for (let counter = 0; counter < chunksOf32; counter++) {
        const copyLen = Math.min(32, size - p_buffer_index);

        const buffer32 = Buffer.from(buffer.subarray(p_buffer_index, p_buffer_index + copyLen));

        buffer32.writeUint32LE(0, 4);

        const chunk_offset = (offset + p_buffer_index) >>> 0;

        const hashValue = hashDevType0(buffer32, 32, chunk_offset);

        end = (end + hashValue) >>> 0;

        p_buffer_index += 32;
    }

    return end;
};

/**
 * 
 * @param {number} num
 * @param {number} useSub 
 */
function getType3ByteOffset1(num, useSub) {
    return useSub ? Type3ByteOffset1[num + 512] : Type3ByteOffset1[num];
};

/**
 * 
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {number} useSub 
 */
function addByteOffset1(buffer, offset, useSub) {
    let byteOffset = getType3ByteOffset1(buffer[offset], useSub);

    let pos = offset + 2 * byteOffset;

    let counter = 0;

    while (true) {
        counter++;
        const wordPos = pos + 2 * counter - 2;
        if (wordPos + 1 >= buffer.length) break;

        const word = buffer.readUInt16LE(wordPos);
        
        if (word === 0) {
            return byteOffset + counter;
        }
    }
};

/**
 * 
 * @param {Buffer} buffer
 * @param {number} size 
 * @param {number} offset 
 * @param {number} useSub
 * @param {{offset: number, type3Return: number}[]} subB
 * @param {number} useSub
 * @param {number} subBIndex 
 * @param {number} subBCount 
 */
function getShortsToRead(buffer, size, offset, useSub, subB, subBIndex, subBCount) {
    
    const firstByte = buffer[offset];

    if (firstByte !== 0) {
        if (firstByte === 237) {
            
            return addByteOffset1(buffer, offset, useSub);
        } else {
            return getType3ByteOffset1(firstByte, useSub);
        }
    }

    const secondByte = buffer[offset + 1];

    switch (secondByte) {
        case 0:
            if (useSub) {
                for(let i = subBIndex; i < (subBIndex + subBCount); i++){
                    const entry = subB[i];
                    if (offset === entry.offset) {
                        return entry.type3Return;
                    }
                }
            }

            return 1;
        case 1:
            const v1 = buffer.readUInt16LE(offset + 2);
            return 2 * (v1 + 2);
        case 2:
            const v2 = buffer.readUInt16LE(offset + 2);
            return 4 * v2 + 2;
        case 3:
            const dword = buffer.readUInt32LE(offset + 4);

            const word  = buffer.readUInt16LE(offset + 2);
            
            const temp = (BigInt(dword) * BigInt(word) + 1n) & 0xFFFFFFFFn;

            return Number((temp >> 1n) + 4n);
        default:
            return 0;
    }
};

/**
 * type3 hash check
 * 
 * @param {number} num
 * @param {number} offset 
 * @param {number} useSub
 * @param {{offset: number, type3Return: number}[]} subB
 * @param {number} subBIndex 
 * @param {number} subBCount 
 */
function getToHashType0(num, offset, useSub, subB, subBIndex, subBCount) {

    const adj = (num - 14) & 0xFF;
    let result = (adj > 241) ? 0 : Type3ByteOffset2[adj];

    if (useSub) {
        if (num === 115 || num === 236) return 1;
        if (num === 0) {
            for(let i = subBIndex; i < (subBIndex + subBCount); i++){
                const entry = subB[i];
                if (offset === entry.offset) return 1;
            }
        }
    }

    return result;
};

/**
 * type3 hash check
 * 
 * @param {Buffer} buffer
 * @param {number} size 
 * @param {number} offset 
 * @param {number} useSub
 * @param {{offset: number, type3Return: number}[]} subB
 * @param {number} subBIndex 
 * @param {number} subBCount 
 */
function hashDevType3(buffer, size, offset, useSub = 0, subB = [], subBIndex = 0, subBCount = 0) {
    let result = (size + offset) >>> 0;

    let sizeLeft = size;

    let curIndex = 0;

    while (curIndex < size) {
        const curByte = buffer[curIndex];

        const shortsToRead = getShortsToRead(
            buffer, 
            sizeLeft, 
            curIndex, 
            useSub, 
            subB, 
            subBIndex, 
            subBCount
        ) || 1;
        
        const sizeToHash = 2 * shortsToRead;

        if (getToHashType0(
            curByte, 
            curIndex, 
            useSub, 
            subB, 
            subBIndex, 
            subBCount)) {
            result = (result + (curIndex + sizeToHash)) >>> 0;

        } else {
            const chunk = buffer.subarray(curIndex, Math.min(curIndex + sizeToHash, size));

            const hashVal = hashDevType0(chunk, sizeToHash, curIndex);

            result = (result + hashVal) >>> 0;
        }

        curIndex += sizeToHash;

        sizeLeft -= sizeToHash;
    }

    return result;
};

/**
 * data1 type hash check
 * 
 * @param {Buffer} buffer 
 * @param {number} size 
 * @param {number | undefined} MAGIC
 */
function hashData1(buffer, size, MAGIC = 0xBA146891){
    const count = size >> 2;

    const hash = new Uint32Array(1);

    hash[0] = size;

    let i = 0;

    while (i < count) {
        let piVarl = buffer.readUint32LE(i * 4);
        i++;
        hash[0] = i * (MAGIC + piVarl) + hash[0];
    }

    return hash[0];
}

/**
 * Runs a hashCheck on assets/57d5/data1.dat
 * 
 * @param {Buffer} buffer 
 * @param {number | undefined} MAGIC
 */
function hashCheckData1(buffer, MAGIC = 0xBA146891) {
    const target = buffer.readUint32LE(4);
    // must clear the hash location
    buffer.writeUint32LE(0, 4);

    const hash = hashData1(buffer, buffer.byteLength, MAGIC);

    if (hash != target) {
        throw new Error(`data1.dat failed hash check. ${hash} != ${target}`);
    }
};

/**
 * 
 * @param {Buffer} buffer
 * @param {number | undefined} hash1
 * @param {number | undefined} hash2 - doesnt look hardcoded. Found by the file path string
 * @returns {{buffer: Buffer, size: number, offsetStart: number, count: number, entries: {id: number, offsetStart: number, sizeNeeded: number, hash: number}[]}}
 */
function decodeData1Headers(buffer, hash1 = 0x2B4BC95A, hash2 = 0x5DB6A4B0) {
    hashCheckData1(buffer);

    const seed = multiplyInt(buffer.readUint32LE(4 * 4), buffer.readUint32LE(4 * 4));

    const shortValues = new Uint16Array(3);

    var divCount = 3;

    var p = 0;

    do {
        const div5 = divmod(divCount, 5);

        const div11 = divmod(divCount + 4, 11);

        const shortRead = buffer.readUInt16LE(p);

        divCount++;

        shortValues[0] = (seed >> (div5.remainder & 0xFF));

        shortValues[1] = (seed << (div11.remainder & 0xFF));

        shortValues[2] = (shortRead - shortValues[0] + shortValues[1]);

        buffer.writeUInt16LE(shortValues[2], p);

        p += 2;
    } while (divCount != 19);

    if (buffer.readUint32LE(0) != hash1) {
        throw new Error(`data1.dat failed first hash check. ${buffer.readUint32LE(0)} != ${hash1}`);
    }

    //if (buffer.readUint32LE(2 * 4) != hash2) {
    //    throw new Error(`data1.dat failed second hash check. ${buffer.readUint32LE(2 * 4)} != ${hash2}`);
    //}

    divCount = buffer.readUint32LE(4 * 6) >> 1;

    const total = (16 * buffer.readUint32LE(4 * 7) + 32) >> 1;

    p = divCount * 2;

    while (divCount < total) {
        const div5 = divmod(divCount + 7, 11);

        const div11 = divmod(divCount + 3, 5);

        const shortRead = buffer.readUInt16LE(p);

        ++divCount;

        shortValues[0] = (seed << (div5.remainder & 0xFF));

        shortValues[1] = (seed >>> (div11.remainder & 0xFF));

        shortValues[2] = (shortRead + shortValues[0] - shortValues[1]);

        buffer.writeUInt16LE(shortValues[2], p);

        p += 2;
    }

    return readData1Entries(buffer);
};

/**
 * 
 * @param {{buffer: Buffer, size: number, offsetStart: number, count: number, entries: {id: number, offsetStart: number, sizeNeeded: number, hash: number}[]}} meta 
 * @param {number} entryID 
 * @param {number} [seed=undefined] 
 */
function readData1Entry(meta, entryID, seed = undefined) {
    // entry 4   seed = 0xCC29E208 - clasess.dex check
    // entry 5   seed = 0xF684A9 - Lib hash check
    // entry 7   seed = 0x97045CC - asset check
    // entry 8   seed = 0x709ACA1D - AndroidManifest.xml
    // entry 128 seed = 0xF86CFF96 - Intel 386
    // entry 129 seed = 0x2D800665 - Arm
    // entry 136 seed = 0xE788FB20 - Intel 386
    // entry 137 seed = 0xDAC08FCD - Arm
    // entry 132 seed = 0x03D2270F - x86_64
    // entry 133 seed = 0x01BF26DA - Arm64
    if(seed == undefined){
        switch (entryID) {
            case 4: // clasess.dex check
                seed = 0xCC29E208;
                break;
            case 5: // Lib hash check
                seed = 0xF684A9;
                break; 
            case 7: // asset check
                seed = 0x97045CC;
                break;
            case 8: // AndroidManifest.xml
                seed = 0x709ACA1D;
                break;
            case 128: // Intel 386
                seed = 0xF86CFF96;
                break;
            case 129: // Arm
                seed = 0x2D800665;
                break;
            case 136: // Intel 386
                seed = 0xE788FB20;
                break;
            case 137: // Arm
                seed = 0xDAC08FCD;
                break;
            case 132: // x86_64
                seed = 0x03D2270F;
                break;
            case 133: // Arm64
                seed = 0x01BF26DA;
                break;
            default:
                break;
        }
    }

    if(seed == undefined){
        throw new Error("Seed can not be undefined");
    }

    var entryIndex = meta.entries.findIndex(self => self.id == entryID);

    if (entryIndex == -1) {
        const list = meta.entries.map(self => self.id);

        throw new Error(`Didn't find entryID of ${entryID} in array. ${JSON.stringify(list)}`);
    }

    const shortValues = new Uint16Array(4);

    const buffer = meta.buffer;

    const Entry = meta.entries[entryIndex];

    const count = Entry.sizeNeeded >> 1;

    var p = Entry.offsetStart;

    const mod = new Uint32Array(3);

    for (let i = 0; i < count; i++) {
        const shortRead = buffer.readUInt16LE(p);

        var div11 = udivmod(i + 3, 11);

        var div17 = udivmod(i + 7, 17);

        mod[0] = 0x21E83B7B;

        shortValues[0] = (multiplyInt(seed, seed) >>> (div11.remainder & 0xFF));

        shortValues[1] = (multiplyInt(seed, seed) << (div17.remainder & 0xFF));

        shortValues[2] = ((shortRead + shortValues[0]) - shortValues[1]);

        buffer.writeUInt16LE(shortValues[2], p);

        div11 = udivmod(i * i, 9);

        mod[1] = ((multiplyInt(seed, (mod[0] + seed) >>> 0) << (div11.remainder & 0xFF)) + seed) >>> 0;

        mod[0] = 0xC9FE98D2 + mod[1]

        mod[2] = 0x830AADBE + mod[1];

        div11 = udivmod(i, 23);

        let modmod = multiplyInt(mod[1], mod[0]);

        seed = (mod[2] - (modmod >>> (div11.remainder & 0xFF))) >>> 0;

        p += 2;
    }

    const ret = buffer.subarray(Entry.offsetStart, Entry.offsetStart + Entry.sizeNeeded);
    //FS.hexdump(ret, { length: ret.length});
    return ret;
}

/**
 * Creates seed for table92
 * 
 * Reads 8
 * 
 * @param {Buffer} buffer 
 * @param {number} type 
 */
function decodeSeedMaster(buffer, type = 226) {
    const MUL_CONST = 0x9D323CD7;

    const v16 = (MUL_CONST * type) & 0xFFFFFFFF;

    const shiftAmount = type & 7;

    const leftShift = type & 0xB;

    const v15 = ((v16 >>> shiftAmount) + 0x5E727D74) & 0xFFFFFFFF;

    const v14 = ((v16 << leftShift) - 0x8E1CFFB) & 0xFFFFFFFF;

    const seed = ((v15 + v14) & 0xFFFFFFFF) >>> 0;

    const word0 = buffer.readUint32LE(0);

    const word1 = buffer.readUint32LE(4);

    let startAdd = 0xCBF0C1D8;

    const decoded = new Uint32Array(2);

    for (let i = 0; i < 8; i += 4) {
        const idx = i / 4; // 0 or 1

        const tmpHolder = idx === 0 ? word0 : word1;

        let currentValue = tmpHolder + startAdd;

        currentValue &= 0xFFFFFFFF;

        const xorResult = makeXor(currentValue);

        const constantPart = (0xEBE81DBA * (i + 1) + seed) & 0xFFFFFFFF;

        decoded[idx] = (constantPart ^ xorResult) >>> 0;

        startAdd = tmpHolder;
    }

    return ((decoded[1] + seed) & 0xFFFFFFFF) >>> 0;
};

/**
 * Creates seed type 243 decode
 * 
 * Reads 8
 * 
 * @param {Buffer} buffer
 * @param {number} [type=227]  starts with 227, then 228
 */
function decodeSeedSub(buffer, type = 227) {
    const MUL_CONST = 0x9D323CD7;

    var product = multiplyInt(MUL_CONST, type);

    var rightTerm = product >>> (type & 7);

    var leftTerm = (product << (type & 0xB)) >>> 0;

    const seed = (rightTerm + leftTerm) >>> 0;

    var word0 = buffer.readUint32LE(0);

    const v7 = word0;

    var word1 = buffer.readUint32LE(4);

    rightTerm = (seed + 0x4178CB33) >>> 0;

    leftTerm = (word0 - 0x340F3E28) >>> 0;

    word0 = (makeXor(leftTerm) ^ rightTerm) >>> 0;

    buffer.writeUint32LE(word0, 0);

    rightTerm = (v7 + word1) >>> 0;

    const Xor = makeXor(rightTerm);

    let subTerm = (seed - 0xEE6BDE5) >>> 0;

    let xorTerm = Xor ^ subTerm;

    return (seed + 0x5590AD79 + xorTerm) >>> 0;
};

/**
 * Decodes next Lv Offsets
 * 
 * @param {Buffer} buffer 
 * @param {number} i 
 * @param {number} SHT_LOUSER_SEED 
 */
function decodeSubTableMaster(buffer, i, SHT_LOUSER_SEED) {
    var startSeed92 = (0xF02F7685) >>> 0;

    buffer = buffer.subarray(i * 92, buffer.byteLength);

    for (let z = 0; z < 92; z += 4) {
        const inInt = buffer.readUint32LE(z);

        const subXORMuli = multiplyInt(startSeed92, startSeed92);

        const subXOR = (subXORMuli >>> 3);

        const XOR_IN = (subXOR ^ inInt) >>> 0;

        const Xor = makeXor(XOR_IN);

        startSeed92 = inInt;

        var term1 = multiplyInt(SHT_LOUSER_SEED, SHT_LOUSER_SEED - 0x6909F48F);

        term1 = (term1 << ((i + 1) & 3)) >>> 0;

        term1 = (term1 ^ Xor) >>> 0;

        var term2 = multiplyInt(0x79934CF6, z + 1);

        var term3 = SHT_LOUSER_SEED;

        var term4 = multiplyInt(SHT_LOUSER_SEED, SHT_LOUSER_SEED - 0x626498C3);

        term4 = term4 >>> ((z + 3) & 5);

        var writeValue = ((term1 + term2) >>> 0);

        writeValue = (writeValue + term3) >>> 0;

        writeValue = (writeValue - term4) >>> 0;

        buffer.writeUint32LE(writeValue, z);
    }

    return readSubTable(buffer);
};

/**
 * Decodes next Lv Offsets
 * 
 * @param {Buffer} buffer 
 * @param {number} i 
 * @param {number} TYPE_243_SEED 
 * @param {number} offset 
 */
function decodeSubTableSub(buffer, i, TYPE_243_SEED, offset) {
    const seed = TYPE_243_SEED;

    var seedCounter = 0x79934CF6;

    const seedMulti = multiplyInt(seed, (seed - 0x6909F48F) >>> 0);

    const seedAdd = (seedMulti + multiplyInt(0x6A55BCC, seed)) >>> 0;

    var seedStart = 0xF02F7685;

    const notByte = (~(offset & 0xFF) >>> 0) & 0xFF;

    const seedMultiShift = (seedMulti << ((i + 1) & 3)) >>> 0;

    var pos = 0;

    do {
        const intInt = buffer.readUInt32LE(pos);

        pos += 4;

        let seedStartProduct = multiplyInt(seedStart, seedStart);

        let shiftVal = seedStartProduct >>> 3;

        let Xor = makeXor(intInt ^ shiftVal);

        seedStart = intInt;

        let addValue = ((Xor ^ seedMultiShift) + seedCounter + seed) >>> 0;

        seedCounter = (seedCounter - 0x19B2CC28) >>> 0;

        let shiftAmount = ((notByte + ((pos + offset) & 0xFF)) & 0xFF) & 5;

        let writeVal = (addValue - (seedAdd >>> shiftAmount)) >>> 0;

        buffer.writeUInt32LE(writeVal, pos - 4);
    } while (seedCounter != 0x2A82F55E);

    return readSubTable(buffer);
};

/**
 * Decodes next Lv Offsets
 * 
 * @param {Buffer} buffer 
 * @param {number} seed 
 */
function decodeSubTable157(buffer, seed) {
    var offset = 0;

    for (let i = 0; i != 23; ++i) {
        const P = multiplyInt(seed, (seed - 0x2C178EBC) >>> 0);

        const shift1 = (i * 4) & 7;

        const shiftedP = (P << shift1) >>> 0;

        const term1 = (buffer.readUint32LE(offset + (i * 4)) - shiftedP) >>> 0;

        const Q = multiplyInt(0xBD9418D, seed);

        const sum = (P + Q) >>> 0;

        const shift2 = (i * 4 + seed) & 7;

        const term2 = sum >>> shift2;

        buffer.writeUint32LE((term1 ^ term2) >>> 0, offset + (i * 4));
    }

    return readSubTable(buffer);
}

/**
 * Aligns offset
 * 
 * @param {number} size 
 * @param {number} align 
 * @param {number} alignDown 
 */
function pageAlign(size, align, alignDown) {
    var adj;

    if ((size & (align - 1)) == 0) {
        return size;
    }
    if (alignDown) {
        adj = align;
    }
    else {
        adj = 0;
    }
    return adj + (-align & size);
};

/**
 * 
 * @param {Buffer} buffer SHT_LOUSER_AFTER_MASTER_START_PlusSliceTableOffset
 * @param {Buffer} AES_TABLE 
 * @param {number | undefined} startSeed
 * @param {Buffer | undefined} nextELFBuffer
 */
function decodeNextLvSub(buffer, AES_TABLE, startSeed = 0x5378, nextELFBuffer = undefined) {
    const seed = ((multiplyInt(startSeed, startSeed) >> 17) ^ (multiplyInt(startSeed, startSeed) << 11)) >>> 0;

    var offset = 0;

    var size = buffer.readUint32LE(offset);

    offset += 4;

    const Xor = makeXor(size);

    var term1 = multiplyInt(0x784CC84, seed);

    var term2 = (0xA21DFB3A << (seed & 7)) >>> 0;

    size = (((term2 - term1) >>> 0) + Xor) >>> 0;

    if (nextELFBuffer == undefined) {
        nextELFBuffer = Buffer.alloc(size);
    }

    var sliceEntries = buffer.readUint32LE(offset);

    offset += 4;

    const Xor2 = makeXor(sliceEntries);

    term1 = (0x416E2AF2 >>> (seed & 0xD));

    term2 = (seed - 0x42E639C4 + term1) >>> 0;

    sliceEntries = (term2 ^ Xor2) >>> 0;

    var compTableSize = 0;

    var compTable;

    if (!(sliceEntries > 256)) {
        compTableSize = buffer.readUint32LE(offset);

        offset += 4;

        const xor3 = makeXor(compTableSize);

        term1 = (0x643A3A3B << (seed & 0xB)) >>> 0;

        term2 = seed ^ 0x3B2BF538;

        compTableSize = (term1 - term2 + xor3) >>> 0;
        // max size here of 6912 0x1B00
        compTable = buffer.subarray(offset, offset + compTableSize);

        //console.log("[*] decodeNextLv1", JSON.stringify({
        //    size,
        //    sliceEntries,
        //    compTableSize
        //},null,4));
    }

    if (compTable != undefined) {
        const count = compTableSize >> 2;

        for (let i = 0; i < count; i++) {
            const read = compTable.readUint32LE(i * 4);

            const _xor3 = makeXor(read);

            compTable.writeUint32LE(_xor3, i * 4);
        }

        term1 = multiplyInt(seed, seed - 0xE34A47F);

        var tmpSeed = (term1 - multiplyInt(0x23B32203, seed)) >>> 0;

        for (let j = 0; j < compTableSize; j++) {
            let processedValue = (term1 << (j & 0x1B)) >>> 0;

            let Xor = makeXor(processedValue);

            let term2 = tmpSeed >>> (j & 0x17);

            processedValue = (Xor - term2) >>> (j & 0x1F);

            compTable[j] = (compTable[j] + processedValue) % 256;
        }

        offset += compTableSize;
    }

    offset = pageAlign(offset, 4, 1);
    // max size here of 2048 0x800
    const sliceTable = buffer.subarray(offset, offset + (8 * sliceEntries));

    var tmpSeed2 = multiplyInt(seed - 0x4CE0BAE4, seed);

    var tmpSeed3 = (tmpSeed2 - multiplyInt(0x822FE82D, seed)) >>> 0;

    var tmpSeed4 = (8 * tmpSeed2) >>> 0;

    var k = 0;

    while (k < (2 * sliceEntries)) {
        let read = sliceTable.readUint32LE(k * 4);

        let term1 = makeXor(read ^ tmpSeed4);

        let term2 = (tmpSeed3 >>> (((k * 4) & 7) + 5));

        read = (term1 + term2) >>> 0;

        sliceTable.writeUint32LE(read, k * 4);

        k++;
    }

    for (let i = 0; i < 8 * sliceEntries; i += 8) {
        const sliceoffset = sliceTable.readUint32LE(i);
        // when buffer is created they add an extra 16 bytes
        const sliceSize = sliceTable.readUint32LE(i + 4);

        const src = buffer.subarray(sliceoffset, sliceoffset + sliceSize);

        const tmp = Buffer.alloc(sliceSize + 0x10);

        tmp.set(src, 0);

        PRNG_SLICE(tmp, sliceSize, startSeed);

        decryptSlice(tmp, AES_TABLE, sliceSize);
        // @ts-ignore
        readDecompHeader(compTable, nextELFBuffer, tmp);
    }

    offset += 8 * sliceEntries;

    console.log(`[!] Size:`, offset);

    return nextELFBuffer;
};

/**
 * 
 * @param {Buffer} buffer SHT_LOUSER_AFTER_MASTER_START_PlusSliceTableOffset
 * @param {Buffer} AES_TABLE 
 * @param {number | undefined} startSeed
 * @param {Buffer | undefined} nextELFBuffer
 */
function decodeNextLvMaster(buffer, AES_TABLE, startSeed = 0x745F, nextELFBuffer = undefined) {
    const seed = (multiplyInt(startSeed, startSeed) << 11) ^ (multiplyInt(startSeed, startSeed) >> 17);

    var offset = 0;

    var size = buffer.readUint32LE(offset);

    offset += 4;

    const Xor = makeXor(size);

    var term1 = multiplyInt(0xF87B337C, seed);

    var term2 = (0xA21DFB3A << (seed & 7)) >>> 0;

    size = (((term1 + term2) >>> 0) + Xor) >>> 0; // size

    if (nextELFBuffer == undefined) {
        nextELFBuffer = Buffer.alloc(size);
    }

    var sliceEntries = buffer.readUint32LE(offset);

    offset += 4;

    const Xor2 = makeXor(sliceEntries);

    term1 = (0x416E2AF2 >>> (seed & 0xD));

    term2 = (term1 + seed - 0x42E639C4) >>> 0;

    sliceEntries = (Xor2 ^ term2) >>> 0;

    var compTableSize = 0;

    var compTable;

    if (!(sliceEntries > 256)) {
        compTableSize = buffer.readUint32LE(offset);

        offset += 4;

        const xor3 = makeXor(compTableSize);

        term1 = (0x643A3A3B << (seed & 0xB)) >>> 0;

        term2 = seed ^ 0x3B2BF538;

        compTableSize = (term1 - term2 + xor3) >>> 0;
        // max size here of 6912 0x1B00
        compTable = buffer.subarray(offset, offset + compTableSize);

        //console.log("[*] decodeNextLv", JSON.stringify({
        //    size,
        //    sliceEntries,
        //    compTableSize,
        //    offset
        //},null,4));
    }

    if (compTable != undefined) {
        const count = compTableSize >> 2;

        for (let i = 0; i < count; i++) {
            const read = compTable.readUint32LE(i * 4);

            const _xor3 = makeXor(read);

            compTable.writeUint32LE(_xor3, i * 4);
        }

        term1 = multiplyInt(seed, seed - 0xE34A47F);

        let tmpSeed = multiplyInt(seed, seed - 0x31E7C682);

        for (let j = 0; j < compTableSize; j++) {
            let processedValue = (term1 << (j & 0x1B)) >>> 0;

            let xor = makeXor(processedValue);

            let term2 = tmpSeed >>> (j & 0x17);

            processedValue = (xor - term2) >>> (j & 0x1F);

            compTable[j] = (compTable[j] + processedValue) % 256;
        }

        offset += compTableSize;
    }

    offset = pageAlign(offset, 4, 1);
    // max size here of 2048 0x800
    const sliceTable = buffer.subarray(offset, offset + (8 * sliceEntries));

    const subEntry = 8 * sliceEntries;

    for (let k = 0; k < subEntry; k += 4) {
        let read = sliceTable.readUint32LE(k);

        let term1 = multiplyInt(seed - 0x4CE0BAE4, seed);

        term1 = (term1 << ((k & 3) + 3)) >>> 0;

        read ^= term1;

        read >>>= 0;

        let v10 = makeXor(read);

        let term2 = multiplyInt(seed + 0x30EF5CEF, seed);

        term2 = term2 >>> ((k & 7) + 5);

        read = (v10 + term2) >>> 0;

        sliceTable.writeUint32LE(read, k);
    }

    for (let i = 0; i < subEntry; i += 8) {
        const sliceoffset = sliceTable.readUint32LE(i);
        // when buffer is created they add an extra 16 bytes
        const sliceSize = sliceTable.readUint32LE(i + 4);

        const src = buffer.subarray(sliceoffset, sliceoffset + sliceSize);

        const tmp = Buffer.alloc(sliceSize + 0x10);

        tmp.set(src, 0);

        PRNG_SLICE(tmp, sliceSize, startSeed);

        decryptSlice(tmp, AES_TABLE, sliceSize);
        // @ts-ignore
        readDecompHeader(compTable, nextELFBuffer, tmp);
    }

    offset += subEntry;

    console.log(`[!] Size:`, offset);

    return nextELFBuffer;
}

/**
 * Decode a string from a buffer
 * 
 * @param {Buffer} buffer 
 * @param {number} len 
 * @returns {string}
 */
function DoDecodeString2(buffer, len) {
    let i = 0;
    for (i = 0; i < len; ++i) {
        let v2 = buffer[i];

        if (!v2) {
            break;
        }

        buffer[i] = ~((v2 >> 3) | (32 * v2)) - (i & 3);
    }
    return buffer.subarray(0, i).toString();
};

module.exports = {
    PRNG,
    decodeELF,
    DecodeMasterTable,
    DoDecodeString,
    DoDecodeString2,
    decodeData1Headers,
    PRNG_MASTER,
    decodeSeedMaster,
    decodeSeedSub,
    decodeSubTableMaster,
    decodeSubTableSub,
    decodeSubTable157,
    decodeNextLvMaster,
    decodeNextLvSub,
    pageAlign,
    readData1Entry,
    hashDevType0,
    hashDevType1,
    hashDevType2,
    hashDevType3,
    hashData1
};