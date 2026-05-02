// @ts-check

const { PRNG } = require('./Decode');
const { decryptSlice } = require('./Decryption');
const { decompressSlice } = require('./Decompress');

/**
 * Lib name VIA types
 * 
 * @type {{[key: string]: string}}
 */
const libNames = {
    // Lv0
    "5":   "dllidlist.so",
    "4":   "setupDT_NEEDED.so",
    "1":   "dthelper.so",
    "2":   "ht_lookup_lite.so",
    "3":   "ht_lookup.so",
    "6":   "libht_reloc_ndk.so",
    "8":   "libht_decode.so",
    "9":   "libht_mutex.so",
    // Lv1
    "144": "libtest.so",
    "16":  "liboptapkchk.so",
    "18":  "liboptcertchk.so",
    "19":  "liboptcoredumpgrd.so",
    "20":  "liboptdalvikchk.so",
    "21":  "liboptddmsgrd.so",
    "22":  "liboptdebuggrd.so",
    "23":  "liboptdexchk.so",
    "24":  "liboptemuchk.so",
    "26":  "liboptloadpathchk.so",
    "27":  "liboptnotifylog.so",
    "28":  "liboptodexchk.so",
    "29":  "liboptprotectmem.so",
    "146": "data146.bin", // AKA CP Data
    "145": "libOptCommonExec.so",
    // Lv2
    "248": "data248.bin", // This data gets decoded again and applied directly to the master lib
    "241": "data241.bin", // The symbol and string table to be added back to the master lib
    "242": "lib242.so",   // no code DT tables
    "240": "libLvDecode.so"
};

const LV_ENTRY_SIZE = 0x44;

/**
 * Reads Lv Info
 * 
 * @param {Buffer} inputBuffer 
 * @param {number} offset 
 */
function readLvInfo(inputBuffer, offset){
    if(offset + LV_ENTRY_SIZE > inputBuffer.byteLength){
        throw new Error("Buffer too short to read LvInfo.");
    }

    return {
        masterElfSize:  inputBuffer.readUint32LE(offset + 0x00),
        mprotect:       inputBuffer.readUint32LE(offset + 0x04),
        mprotectStart:  inputBuffer.readUint32LE(offset + 0x08),
        mprotectSize:   inputBuffer.readUint32LE(offset + 0x0C),
        funcPassOffset: inputBuffer.readUint32LE(offset + 0x10),
        tableOffset:    inputBuffer.readUint32LE(offset + 0x14),
        tableSize:      inputBuffer.readUint32LE(offset + 0x18),
        elfchunkOffset: inputBuffer.readUint32LE(offset + 0x1C),
        elfchunkSize:   inputBuffer.readUint32LE(offset + 0x20),
        unk24:          inputBuffer.readUint32LE(offset + 0x24),
        unk28:          inputBuffer.readUint32LE(offset + 0x28),
        unk2C:          inputBuffer.readUint32LE(offset + 0x2C),
        unk30:          inputBuffer.readUint32LE(offset + 0x30),
        unk34:          inputBuffer.readUint32LE(offset + 0x34),
        unk38:          inputBuffer.readUint32LE(offset + 0x38),
        unk3C:          inputBuffer.readUint32LE(offset + 0x3C),
        NextLvInfo:     inputBuffer.readUint32LE(offset + 0x40),
    }
};

const TABLE_ENTRY_SIZE = 0x38;

/**
 * Reads Table Info
 * 
 * @param {Buffer} inputBuffer 
 * @param {number} offset 
 */
function readTableEntry(inputBuffer, offset){
    if(inputBuffer.byteLength < offset + TABLE_ENTRY_SIZE){
        throw new Error(`Buffer too short to read table. ${inputBuffer.byteLength} < ${offset + TABLE_ENTRY_SIZE}`);
    }

    return {
        type:              inputBuffer.readUint32LE(offset + 0x00),
        name:              libNames[inputBuffer.readUint32LE(offset + 0x00)] || "",
        flag:              inputBuffer.readUint32LE(offset + 0x04),
        ELFHeaderParse:    (inputBuffer.readUint32LE(offset + 0x04) & 0x10000) == 0,
        HtLoadLibrary:     (inputBuffer.readUint32LE(offset + 0x04) & 0x200) != 0,
        convertFuncExport: (inputBuffer.readUint32LE(offset + 0x04) & 0x100) != 0,
        distSize:          inputBuffer.readUint32LE(offset + 0x08),
        mprotect:          inputBuffer.readUint32LE(offset + 0x0C),
        mprotectStart:     inputBuffer.readUint32LE(offset + 0x10),
        mprotectSize:      inputBuffer.readUint32LE(offset + 0x14),
        funcPassOffset:    inputBuffer.readUint32LE(offset + 0x18),
        funcExports:       inputBuffer.readUint32LE(offset + 0x1C),
        exportCount:       inputBuffer.readUint32LE(offset + 0x20),
        data24:            inputBuffer.readUint32LE(offset + 0x24),
        data28:            inputBuffer.readUint32LE(offset + 0x28),
        offsetWithinMaster:inputBuffer.readUint32LE(offset + 0x2C),
        sizeWithinMaster:  inputBuffer.readUint32LE(offset + 0x30),
        data34:            inputBuffer.readUint32LE(offset + 0x34),
    }
};

/**
 * Reads master chunk headers
 * 
 * @param {Buffer} inputBuffer 
 */
function readMasterChunk(inputBuffer){
    if(inputBuffer.byteLength < 0x1C){
        throw new Error("Buffer too short to header chunk.");
    }

    const reObj = {};

    reObj.chunkELFStart   = inputBuffer.readUint32LE(0x00);
    reObj.metaStart       = inputBuffer.readUint32LE(0x08);
    reObj.metaCount       = inputBuffer.readUint32LE(0x0C);
    reObj.compTableStart  = inputBuffer.readUint32LE(0x10);
    reObj.compTableSize   = inputBuffer.readUint32LE(0x14);
    reObj.roundKeysStart  = inputBuffer.readUint32LE(0x18);
    reObj.roundKeysSize   = inputBuffer.readUint32LE(0x1C);

    /**
     * @type {{srcStart: number, destStart: number, srcSize: number, destSize: number }[]}
     */
    reObj.metas = [];

    if(inputBuffer.byteLength < 0x1C + (reObj.metaCount * 16)){
        throw new Error(`Buffer too short to header meta chunks. ${inputBuffer.byteLength} < ${0x1C + (reObj.metaCount * 16)}`);
    }
    
    for (let i = 0; i < reObj.metaCount; i++) {
        const off = reObj.metaStart + i * 12;
        try {
            reObj.metas.push({
                srcStart:  inputBuffer.readUint32LE(off,   ),
                destStart: inputBuffer.readUint32LE(off + 4),
                srcSize:   inputBuffer.readUint16LE(off + 8),
                destSize:  inputBuffer.readUint16LE(off + 10)
            });
        } catch (error) {
            console.error(error);
        }
    }

    return reObj;
};

/**
 * Create elf from PRNG and sliced chunks
 * 
 * @param {Buffer} ElfChunk 
 * @param {Buffer<ArrayBufferLike> | undefined} MASTER_ELF_BUFFER 
 */
function decodeELF(ElfChunk, MASTER_ELF_BUFFER = undefined){
    PRNG(ElfChunk, ElfChunk.byteLength, ElfChunk.readUint32LE(32));

    const chunkData = readMasterChunk(ElfChunk);

    let totalDestSize = 0;

    if(MASTER_ELF_BUFFER == undefined){
        for (let i = 0; i < chunkData.metas.length; i++) {
            const m = chunkData.metas[i];

            totalDestSize = Math.max(totalDestSize, m.destStart + m.destSize);
        }

        MASTER_ELF_BUFFER = Buffer.alloc(totalDestSize);
    }

    const huffData = chunkData.compTableSize > 0 ? ElfChunk.subarray(chunkData.compTableStart, chunkData.compTableStart + chunkData.compTableSize) : null;

    const sboxData = chunkData.roundKeysSize > 0 ? ElfChunk.subarray(chunkData.roundKeysStart, chunkData.roundKeysStart + chunkData.roundKeysSize) : null;
    // copy buffer
    if(huffData == null && sboxData == null){
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

            if(sboxData != null){
                if (!decryptSlice(srcData, sboxData)) {
                    throw new Error(`AES failed on slice ${i}.`);
                }
            }  
            // Write to final ELF
            if (m.srcSize === m.destSize) {
                srcData.copy(MASTER_ELF_BUFFER, m.destStart, 0, m.destSize);
            } else {
                const tmpBuffer = Buffer.alloc(Math.max(m.srcSize, 32));

                srcData.copy(tmpBuffer, 0, 0, m.srcSize);

                const dest = MASTER_ELF_BUFFER.subarray(m.destStart, m.destStart + m.destSize);

                if(huffData != null){
                    if (!decompressSlice(huffData, tmpBuffer, m.srcSize, dest)) {
                        throw new Error(`Decompress failed on slice ${i}.`);
                    }
                } 
            }
        }
    }

    return MASTER_ELF_BUFFER;
};

/**
 * Gets the Symbol and String table offsets in the master lib (32 bit)
 * 
 * @param {Buffer} elfBuffer 
 */
function praseELF32(elfBuffer){
    const PHTOff        = elfBuffer.readUint32LE(0x1C);

    const PHTEntrySize  = elfBuffer.readUint16LE(0x2A); // should be 0x20 for 32 bit

    const PHTEntryCount = elfBuffer.readUint16LE(0x2C);

    var DYNAMICOff = 0;

    var DYNAMICSize = 0

    for (let i = 0; i < PHTEntryCount; i++) {
        const entryOff = PHTOff + (i * PHTEntrySize) ;
        
        const PHTType = elfBuffer.readUint32LE(entryOff);

        if(PHTType == 2){ //DYNAMIC
            DYNAMICOff  = elfBuffer.readUint32LE(entryOff + 0x4 );

            DYNAMICSize = elfBuffer.readUint32LE(entryOff + 0x10);
            break;
        }
    }

    if(DYNAMICOff == 0 || DYNAMICSize == 0){
        throw new Error('Failed to find DYNAMIC offset in master lib.');
    }

    var DT_STRTAB = 0;

    var DT_SYMTAB = 0;

    for (let i = 0; i < DYNAMICSize / 8; i++) {
        const entryOff = DYNAMICOff + (i * 8);

        if(elfBuffer.readUint32LE(entryOff) == 5){
            DT_STRTAB = elfBuffer.readUint32LE(entryOff + 0x4);
        }

        if(elfBuffer.readUint32LE(entryOff) == 6){
            DT_SYMTAB = elfBuffer.readUint32LE(entryOff + 0x4);
        }
        
        if(DT_STRTAB != 0 && DT_SYMTAB != 0){
            break;
        }
    }

    if(DT_STRTAB == 0 || DT_SYMTAB == 0){
        throw new Error("Failed to find symbol and string table offsets in master elf.");
    }

    return {
        DT_STRTAB,
        DT_SYMTAB
    };
};

/**
 * Prase the 241 buffer
 * 
 * @param {Buffer} elfBuffer 
 */
function read241(elfBuffer){
    const SYMTAB_OFF   = elfBuffer.readUint32LE(0x00);

    const SYMTAB_COUNT = elfBuffer.readUint32LE(0x04); 
    // entry size for 32 is 0x10
    const SYMTAB_SIZE  = SYMTAB_COUNT * 0x10; 

    const STRTAB_OFF   = elfBuffer.readUint32LE(0x08);

    const STRTAB_SIZE   = elfBuffer.readUint32LE(0x0C);

    const FILE_END_OFF  = elfBuffer.readUint32LE(0x10);

    const entryStart = 0x14;

    const symbolData = elfBuffer.subarray(entryStart + SYMTAB_OFF, entryStart + SYMTAB_OFF + SYMTAB_SIZE);

    const stringData = elfBuffer.subarray(entryStart + STRTAB_OFF, entryStart + STRTAB_OFF + STRTAB_SIZE);

    return {
        symbolData,
        stringData
    }
}

module.exports = {
    libNames,
    LV_ENTRY_SIZE,
    readLvInfo,
    TABLE_ENTRY_SIZE,
    readTableEntry,
    readMasterChunk,
    decodeELF,
    praseELF32,
    read241
};