// @ts-check


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
function PRNG(buffer, length, key){
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

module.exports = {
    PRNG,
    DoDecodeString
};