
const array = new Uint32Array([0xF2D2B3F1, 0xB1B352, 0, 0]);

const buffer =  Buffer.from(array.buffer, array.byteOffset, array.byteLength)

function DoDecodeString(buffer) {
    for (let i = 0; i < buffer.length && buffer[i] !== 0; i++) {
        buffer[i] = (~((8 * buffer[i]) | (buffer[i] >> 5)) - (i & 3)) & 0xFF;
    }
    return buffer;
}

console.log(DoDecodeString(buffer).toString());