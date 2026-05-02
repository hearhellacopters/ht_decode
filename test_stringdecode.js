
const array = new Uint32Array([0x12F212D2, 0xF61351D3, 0x5332]);

const buffer =  Buffer.from(array.buffer, array.byteOffset, array.byteLength);

/**
 * Decode a string from a buffer
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
}

console.log(DoDecodeString(buffer));