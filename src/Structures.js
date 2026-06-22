// @ts-check

const { FS } = require('./File');

// #region Legacy

/**
 * Lib name VIA types
 * 
 * @type {{[key: string]: string}}
 */
const libNamesLegacy = {
    // Legacy
    // Lv1
    "5": "dlliblist.so",
    "4": "setupDT_NEEDED.so",
    "1": "dthelper.so",
    "2": "ht_lookup_lite.so",
    "3": "ht_lookup.so",
    "6": "libht_reloc_ndk.so",
    "8": "libht_decode.so",
    "9": "libht_mutex.so",
    // Lv2
    "144": "libtest.so",
    "16": "liboptapkchk.so",
    "18": "liboptcertchk.so",
    "19": "liboptcoredumpgrd.so",
    "20": "liboptdalvikchk.so",
    "21": "liboptddmsgrd.so",
    "22": "liboptdebuggrd.so",
    "23": "liboptdexchk.so",
    "24": "liboptemuchk.so",
    "26": "liboptloadpathchk.so",
    "27": "liboptnotifylog.so",
    "28": "liboptodexchk.so",
    "29": "liboptprotectmem.so",
    "146": "data146.dat", // AKA CP Data
    "145": "libOptCommonExec.so",
    // Lv3
    "248": "data248.dat", // This data gets decoded again and applied directly to the master lib
    "241": "data241.dat", // The symbol and string table to be added back to the master lib
    "242": "lib242.so",   // no code DT tables
    "240": "libLvDecode.so"
};

/**
 * Lib name VIA types
 * 
 * @type {{[key: string]: string}}
 */
const libNames = {
    // start / misc
    "225": "master_lib",
    "208": "RWLoadSec",
    "226": "libLv0.so",
    "154": "fileReader",
    "4":   "dexHash.dat", // inside data1.dat
    "5":   "libHash.dat", // inside data1.dat
    "7":   "assetHash.dat", // inside data1.dat
    "8":   "AndroidManifest.xml", // inside data1.dat
    "128": "", // inside data1.dat (Intel 386 version of 129)
    "136": "", // inside data1.dat (Intel 386 version of 127)
    "137": "", // inside data1.dat
    "132": "", // inside data1.dat x86_64
    "133": "", // inside data1.dat Arm64
    "10":  "", // unknown
    // Lv0
    "129": "", // a 129 is also found inside data1.dat but doesn't look the same
    "150": "", // shum func and cross reference
    "243": "data243.dat",
    "227": "libLv1.so",
    // Lv1
    "143": "", // heavy file lifing stuff
    "151": "",
    "142": "", // __57d5__.log also sends emails!
    "244": "data244.dat",
    "228": "libLv2.so",
    // Lv2
    "2":   "",
    "106": "", // blank likely list of game hacker packages to check
    "105": "", // checks for super user and magisk and others packages
    "96":  "",  // & 0x1000000 != 0 checks for vm
    "64":  "",  // & 0x1000000 != 0 calls assets/57d5/data1.dat to check assets and manifest
    "32":  "",  // calls assets/57d5/data1.dat to check libs
    "84":  "",  // & 0x1000000 != 0 checks phone model
    "51":  "",  // & 0x1000000 != 0 calls assets/57d5/data1.dat to check dex files
    "245": "data245.dat",
    "229": "libLv3.so",
    // Lv3
    "83":  "",  // & 0x1000000 != 0 has two more packed libs (both ELF for Intel 386)
    "164": "", // & 0x1000000 != 0
    "88":  "",  // & 0x1000000 != 0 calls assets/57d5/data1.dat inflate 
    "246": "data246.dat",
    "230": "libLv4.so",
    // Lv4
    "3":   "",
    "160": "", // & 0x1000000 != 0
    "247": "data247.dat",
    "231": "libLv5.so",
    // Lv5 & Lv6
    "178": "", // rel / jmp rel linking table
    "176": "", // shell c lib for basic mem and str funcitions
    "185": "", // addresses for locations to copy memset / strcat / chr / cmp / cpy / len address to other libs from Lv6
    "157": "data157.dat", // programming from first offset (non headers)
    "158": "", // dynamic symbols & strings table
    "194": "", // chunk data needing offets in Lv6 (only in 32 bit libs)
    "195": "", // jump bytecode needing offsets re-written (only in 32 bit libs)
    "155": "libLv6.so", // the lib that recreates the master
    "248": "data248.dat",
    "232": "libLv7.so",
    // Lv7
    "152": "libLv8.so"
};

const LV_ENTRY_SIZE = 0x44;

/**
 * Reads Lv Info
 * 
 * @param {Buffer} inputBuffer 
 * @param {number} offset 
 */
function readLvInfo(inputBuffer, offset) {
    if (offset + LV_ENTRY_SIZE > inputBuffer.byteLength) {
        FS.hexdump(inputBuffer);

        console.log("[!] Error: Buffer too short to read LvInfo.");

        process.exit(0);
    }

    return {
        masterElfSize: inputBuffer.readUint32LE(offset + 0x00),
        mprotect: inputBuffer.readUint32LE(offset + 0x04),
        mprotectStart: inputBuffer.readUint32LE(offset + 0x08),
        mprotectSize: inputBuffer.readUint32LE(offset + 0x0C),
        funcPassOffset: inputBuffer.readUint32LE(offset + 0x10),
        tableOffset: inputBuffer.readUint32LE(offset + 0x14),
        tableSize: inputBuffer.readUint32LE(offset + 0x18),
        elfchunkOffset: inputBuffer.readUint32LE(offset + 0x1C),
        elfchunkSize: inputBuffer.readUint32LE(offset + 0x20),
        unk24: inputBuffer.readUint32LE(offset + 0x24),
        unk28: inputBuffer.readUint32LE(offset + 0x28),
        unk2C: inputBuffer.readUint32LE(offset + 0x2C),
        unk30: inputBuffer.readUint32LE(offset + 0x30),
        unk34: inputBuffer.readUint32LE(offset + 0x34),
        unk38: inputBuffer.readUint32LE(offset + 0x38),
        unk3C: inputBuffer.readUint32LE(offset + 0x3C),
        NextLvInfo: inputBuffer.readUint32LE(offset + 0x40),
    }
};

const TABLE_ENTRY_SIZE = 0x38;

/**
 * Reads Table Info
 * 
 * @param {Buffer} inputBuffer 
 * @param {number} offset 
 */
function readTableEntry(inputBuffer, offset) {
    if (inputBuffer.byteLength < offset + TABLE_ENTRY_SIZE) {
        FS.hexdump(inputBuffer);

        console.log(`[!] Error: Buffer too short to read table. ${inputBuffer.byteLength} < ${offset + TABLE_ENTRY_SIZE}`);

        process.exit(0);
    }

    return {
        type: inputBuffer.readUint32LE(offset + 0x00),
        name: libNamesLegacy[inputBuffer.readUint32LE(offset + 0x00)] || "",
        flag: inputBuffer.readUint32LE(offset + 0x04),
        ELFHeaderParse: (inputBuffer.readUint32LE(offset + 0x04) & 0x10000) == 0,
        HtLoadLibrary: (inputBuffer.readUint32LE(offset + 0x04) & 0x200) != 0,
        convertFuncExport: (inputBuffer.readUint32LE(offset + 0x04) & 0x100) != 0,
        distSize: inputBuffer.readUint32LE(offset + 0x08),
        mprotect: inputBuffer.readUint32LE(offset + 0x0C),
        mprotectStart: inputBuffer.readUint32LE(offset + 0x10),
        mprotectSize: inputBuffer.readUint32LE(offset + 0x14),
        funcPassOffset: inputBuffer.readUint32LE(offset + 0x18),
        funcExports: inputBuffer.readUint32LE(offset + 0x1C),
        exportCount: inputBuffer.readUint32LE(offset + 0x20),
        data24: inputBuffer.readUint32LE(offset + 0x24),
        data28: inputBuffer.readUint32LE(offset + 0x28),
        offsetWithinMaster: inputBuffer.readUint32LE(offset + 0x2C),
        sizeWithinMaster: inputBuffer.readUint32LE(offset + 0x30),
        data34: inputBuffer.readUint32LE(offset + 0x34),
    }
};

/**
 * Reads master chunk headers
 * 
 * @param {Buffer} inputBuffer 
 */
function readMasterChunk(inputBuffer) {
    if (inputBuffer.byteLength < 0x1C) {
        console.log("[!] Error: Buffer too short to header chunk.");

        process.exit(0);
    }

    const reObj = {
        chunkELFStart: inputBuffer.readUint32LE(0x00),
        metaStart: inputBuffer.readUint32LE(0x08),
        metaCount: inputBuffer.readUint32LE(0x0C),
        compTableStart: inputBuffer.readUint32LE(0x10),
        compTableSize: inputBuffer.readUint32LE(0x14),
        roundKeysStart: inputBuffer.readUint32LE(0x18),
        roundKeysSize: inputBuffer.readUint32LE(0x1C),
        /**
         * @type {{srcStart: number, destStart: number, srcSize: number, destSize: number }[]}
         */
        metas: []
    };

    if (inputBuffer.byteLength < 0x1C + (reObj.metaCount * 16)) {
        FS.hexdump(inputBuffer);

        console.log(`[!] Error: Buffer too short to header meta chunks. ${inputBuffer.byteLength} < ${0x1C + (reObj.metaCount * 16)}`);

        process.exit(0);
    }

    for (let i = 0; i < reObj.metaCount; i++) {
        const off = reObj.metaStart + i * 12;
        try {
            reObj.metas.push({
                srcStart: inputBuffer.readUint32LE(off,),
                destStart: inputBuffer.readUint32LE(off + 4),
                srcSize: inputBuffer.readUint16LE(off + 8),
                destSize: inputBuffer.readUint16LE(off + 10)
            });
        } catch (error) {
            console.error(error);
        }
    }

    return reObj;
};

/**
 * Gets the Symbol and String table offsets in the master lib (32 bit)
 * 
 * @param {Buffer} elfBuffer 
 */
function parseELFSymbolAndString32(elfBuffer) {
    const PHTOff = elfBuffer.readUint32LE(0x1C);

    const PHTEntrySize = elfBuffer.readUint16LE(0x2A); // should be 0x20 for 32 bit

    const PHTEntryCount = elfBuffer.readUint16LE(0x2C);

    var DYNAMICOff = 0;

    var DYNAMICSize = 0

    for (let i = 0; i < PHTEntryCount; i++) {
        const entryOff = PHTOff + (i * PHTEntrySize);

        const PHTType = elfBuffer.readUint32LE(entryOff);

        if (PHTType == 2) { //DYNAMIC
            DYNAMICOff = elfBuffer.readUint32LE(entryOff + 0x4);

            DYNAMICSize = elfBuffer.readUint32LE(entryOff + 0x10);
            break;
        }
    }

    if (DYNAMICOff == 0 || DYNAMICSize == 0) {
        FS.hexdump(elfBuffer);

        console.log('[!] Error: Failed to find DYNAMIC offset in master lib.');

        process.exit(0);
    }

    var DT_STRTAB = 0;

    var DT_SYMTAB = 0;

    for (let i = 0; i < DYNAMICSize / 8; i++) {
        const entryOff = DYNAMICOff + (i * 8);

        if (elfBuffer.readUint32LE(entryOff) == 5) {
            DT_STRTAB = elfBuffer.readUint32LE(entryOff + 0x4);
        }

        if (elfBuffer.readUint32LE(entryOff) == 6) {
            DT_SYMTAB = elfBuffer.readUint32LE(entryOff + 0x4);
        }

        if (DT_STRTAB != 0 && DT_SYMTAB != 0) {
            break;
        }
    }

    if (DT_STRTAB == 0 || DT_SYMTAB == 0) {
        FS.hexdump(elfBuffer);

        console.log("[!] Error: Failed to find symbol and string table offsets in master lib.");

        process.exit(0);
    }

    return {
        DT_STRTAB,
        DT_SYMTAB
    };
};

/**
 * Reads the sht secition for 0x80000000
 * 
 * @param {Buffer} inputBuffer 
 */
function readSHT_LOUSER32(inputBuffer) {
    const SHTFileOffset = inputBuffer.readUint32LE(0x20);

    const SHTEntrySize = inputBuffer.readUint16LE(0x2E);

    if (SHTEntrySize != 0x28) {
        console.log("Warning!: SHTEntrySize != 40", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x30);

    var SHT_LOUSER = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x28);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 2147483648) { // 0x80000000
            SHT_LOUSER = inputBuffer.readUint32LE(SHTEntry + 0x10);

            break;
        }
    }

    return SHT_LOUSER;
};

/**
 * Reads the sht secition for 11
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHT_DYNAMICAddress32(inputBuffer) {
    const SHTFileOffset = inputBuffer.readUint32LE(0x20);

    const SHTEntrySize = inputBuffer.readUint16LE(0x2E);

    if (SHTEntrySize != 0x28) {
        console.log("Warning!: SHTEntrySize != 40", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x30);

    var SHT_DYNSYM = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x28);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 11) { // SHT_DYNSYM
            SHT_DYNSYM = inputBuffer.readUint32LE(SHTEntry + 0x10);

            break;
        }
    }

    return SHT_DYNSYM;
};

/**
 * Reads the sht secition for 11
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHT_DYNAMICAddress64(inputBuffer) {
    const SHTFileOffset = Number(inputBuffer.readBigUInt64LE(0x28));

    const SHTEntrySize = inputBuffer.readUint16LE(0x3A);

    if (SHTEntrySize != 0x40) {
        console.log("Warning!: SHTEntrySize != 64", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x3C);

    var SHT_DYNSYM = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x40);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 11) { // SHT_DYNSYM
            SHT_DYNSYM = Number(inputBuffer.readBigUInt64LE(SHTEntry + 0x18));

            break;
        }
    }

    return SHT_DYNSYM;
};

/**
 * Reads the sht secition for 3
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHT_STRTABAddress32(inputBuffer) {
    const SHTFileOffset = inputBuffer.readUint32LE(0x20);

    const SHTEntrySize = inputBuffer.readUint16LE(0x2E);

    if (SHTEntrySize != 0x28) {
        console.log("Warning!: SHTEntrySize != 40", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x30);

    var SHT_STRTAB = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x28);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 3) { // SHT_STRTAB
            SHT_STRTAB = inputBuffer.readUint32LE(SHTEntry + 0x10);

            break;
        }
    }

    return SHT_STRTAB;
}

/**
 * Reads the sht secition for 11
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHT_DYNAMICSize32(inputBuffer) {
    const SHTFileOffset = inputBuffer.readUint32LE(0x20);

    const SHTEntrySize = inputBuffer.readUint16LE(0x2E);

    if (SHTEntrySize != 0x28) {
        console.log("Warning!: SHTEntrySize != 40", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x30);

    var SHT_DYNSYM = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x28);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 11) { // SHT_DYNSYM
            SHT_DYNSYM = inputBuffer.readUint32LE(SHTEntry + 0x14);

            break;
        }
    }

    return SHT_DYNSYM;
};

/**
 * Reads the sht secition for 0x80000000
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHT_DYNAMICSize64(inputBuffer) {
    const SHTFileOffset = Number(inputBuffer.readBigUInt64LE(0x28));

    const SHTEntrySize = inputBuffer.readUint16LE(0x3A);

    if (SHTEntrySize != 0x40) {
        console.log("Warning!: SHTEntrySize != 64", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x3C);

    var SHT_DYNSYM = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x40);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 11) { // SHT_DYNSYM
            SHT_DYNSYM = Number(inputBuffer.readBigUInt64LE(SHTEntry + 0x20));

            break;
        }
    }

    return SHT_DYNSYM;
};

/**
 * Reads the sht secition for 0x80000000
 * 
 * @param {Buffer} inputBuffer 
 */
function readSHT_LOUSER32_SIZE(inputBuffer) {
    const SHTFileOffset = inputBuffer.readUint32LE(0x20);

    const SHTEntrySize = inputBuffer.readUint16LE(0x2E);

    if (SHTEntrySize != 0x28) {
        console.log("Warning!: SHTEntrySize != 40", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x30);

    var SHT_LOUSER_SIZE = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x28);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 2147483648) { // 0x80000000
            SHT_LOUSER_SIZE = inputBuffer.readUint32LE(SHTEntry + 0x14);

            break;
        }
    }

    return SHT_LOUSER_SIZE;
};

/**
 * Reads the sht secition for 0x80000000
 * 
 * @param {Buffer} inputBuffer 
 */
function fixData32_SIZE(inputBuffer) {
    const PHOffset = inputBuffer.readUint32LE(0x1C);

    const PHEntrySize = inputBuffer.readUint16LE(0x2A);

    if (PHEntrySize != 0x20) {
        console.log("Warning!: PHEntrySize != 32", PHEntrySize);
    }

    const PHCount = inputBuffer.readUint16LE(0x2C);

    var diff = 0;

    var min = 0;
    
    for (let i = 0; i < PHCount; i++) {
        const PHEntry = PHOffset + (i * PHEntrySize);

        const type = inputBuffer.readUint32LE(PHEntry);

        const offset = inputBuffer.readUint32LE(PHEntry + 0x04);

        if(type == 1 && offset != 0){
            console.log(`[!] Fixing load size.`);

            const vaddr = inputBuffer.readUint32LE(PHEntry + 0x08);

            min = offset;

            const size = inputBuffer.readUint32LE(PHEntry + 0x10);

            diff = (vaddr - offset);

            inputBuffer.writeUint32LE(size + diff, PHEntry + 0x10);

            break;
        }
    }

    return {
        diff,
        min
    }; 
};

/**
 * Reads the sht end secition offset
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHTEndOffset32(inputBuffer) {
    const SHTFileOffset = inputBuffer.readUint32LE(0x20);

    const SHTEntrySize = inputBuffer.readUint16LE(0x2E);

    if (SHTEntrySize != 0x28) {
        console.log("Warning!: SHTEntrySize != 40", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x30);

    return SHTFileOffset + (SHTCount * SHTEntrySize);
};

/**
 * Reads the sht end secition offset
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHTEndOffset64(inputBuffer) {
    const SHTFileOffset = Number(inputBuffer.readBigUInt64LE(0x28));

    const SHTEntrySize = inputBuffer.readUint16LE(0x3A);

    if (SHTEntrySize != 0x40) {
        console.log("Warning!: SHTEntrySize != 64", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x3C);

    return SHTFileOffset + (SHTCount * SHTEntrySize);
};

/**
 * Parse the 241 buffer
 * 
 * @param {Buffer} elfBuffer 
 */
function read241(elfBuffer) {
    const SYMTAB_OFF = elfBuffer.readUint32LE(0x00);

    const SYMTAB_COUNT = elfBuffer.readUint32LE(0x04);
    // entry size for 32 is 0x10
    const SYMTAB_SIZE = SYMTAB_COUNT * 0x10;

    const STRTAB_OFF = elfBuffer.readUint32LE(0x08);

    const STRTAB_SIZE = elfBuffer.readUint32LE(0x0C);

    const FILE_END_OFF = elfBuffer.readUint32LE(0x10);

    const entryStart = 0x14;

    const symbolData = elfBuffer.subarray(entryStart + SYMTAB_OFF, entryStart + SYMTAB_OFF + SYMTAB_SIZE);

    const stringData = elfBuffer.subarray(entryStart + STRTAB_OFF, entryStart + STRTAB_OFF + STRTAB_SIZE);

    return {
        symbolData,
        stringData
    }
};

// #region 64 bit and on

/**
 * Aligns offset
 * 
 * @param {number} size 
 * @param {number} align 
 * @param {number} alignDown 
 */
function pageAlign(size, align, alignDown) {
    var v3; // r3

    if ((size & (align - 1)) == 0) {
        return size;
    }
    if (alignDown) {
        v3 = align;
    }
    else {
        v3 = 0;
    }
    return v3 + (-align & size);
}

/**
 * Reads the sht secition for 0x80000000
 * 
 * @param {Buffer} inputBuffer 
 */
function readSHT_LOUSER64(inputBuffer) {
    const SHTFileOffset = Number(inputBuffer.readBigUInt64LE(0x28));

    const SHTEntrySize = inputBuffer.readUint16LE(0x3A);

    if (SHTEntrySize != 0x40) {
        console.log("Warning!: SHTEntrySize != 64", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x3C);

    var SHT_LOUSER = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x40);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 2147483648) { // 0x80000000
            SHT_LOUSER = Number(inputBuffer.readBigUInt64LE(SHTEntry + 0x18));

            break;
        }
    }

    return SHT_LOUSER;
};

/**
 * Reads the sht secition for 3
 * 
 * @param {Buffer} inputBuffer 
 */
function getSHT_STRTABAddress64(inputBuffer) {
    const SHTFileOffset = Number(inputBuffer.readBigUInt64LE(0x28));

    const SHTEntrySize = inputBuffer.readUint16LE(0x3A);

    if (SHTEntrySize != 0x40) {
        console.log("Warning!: SHTEntrySize != 64", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x3C);

    var SHT_STRTAB = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x40);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 3) {
            SHT_STRTAB = Number(inputBuffer.readBigUInt64LE(SHTEntry + 0x18));

            break;
        }
    }

    return SHT_STRTAB;
};

/**
 * Reads the sht secition for 0x80000000
 * 
 * @param {Buffer} inputBuffer 
 */
function readSHT_LOUSER64_SIZE(inputBuffer) {
    const SHTFileOffset = Number(inputBuffer.readBigUInt64LE(0x28));

    const SHTEntrySize = inputBuffer.readUint16LE(0x3A);

    if (SHTEntrySize != 0x40) {
        console.log("Warning!: SHTEntrySize != 64", SHTEntrySize);
    }

    const SHTCount = inputBuffer.readUint16LE(0x3C);

    var SHT_LOUSER_SIZE = 0;

    for (let i = 0; i < SHTCount; i++) {
        const SHTEntry = SHTFileOffset + (i * 0x40);

        if (inputBuffer.readUint32LE(SHTEntry + 0x4) == 2147483648) { // 0x80000000
            SHT_LOUSER_SIZE = Number(inputBuffer.readBigUInt64LE(SHTEntry + 0x20));

            break;
        }
    }

    return SHT_LOUSER_SIZE;
};

/**
 * Reads the sht secition for 0x80000000
 * 
 * @param {Buffer} inputBuffer 
 */
function fixData64_SIZE(inputBuffer) {
    const PHOffset = Number(inputBuffer.readBigUInt64LE(0x20));

    const PHEntrySize = inputBuffer.readUint16LE(0x36);

    if (PHEntrySize != 0x38) {
        console.log("Warning!: PHEntrySize != 56", PHEntrySize);
    }

    const PHCount = inputBuffer.readUint16LE(0x38);

    var diff = 0n;

    var min = 0;

    for (let i = 0; i < PHCount; i++) {
        const PHEntry = PHOffset + (i * PHEntrySize);

        const type = inputBuffer.readUint32LE(PHEntry);

        const offset = inputBuffer.readBigUInt64LE(PHEntry + 0x08);

        if(type == 1 && offset != 0n){
            console.log(`[!] Fixing load size.`);

            const vaddr = inputBuffer.readBigUInt64LE(PHEntry + 0x10);

            min = Number(offset);

            const size = inputBuffer.readBigUInt64LE(PHEntry + 0x20);

            diff = (vaddr - offset);

            inputBuffer.writeBigUInt64LE(size + diff, PHEntry + 0x20);

            break;
        }
    }

    return {
        diff: Number(diff),
        min
    };
};

/**
 * 
 * @param {Buffer} buffer 
 */
function readData1Entries(buffer) {
    const offsetStart = buffer.readUint32LE(4 * 6);

    const count = buffer.readUint32LE(4 * 7);

    const entries = [];

    for (let i = 0; i < count; i++) {
        const offset = offsetStart + (i * 0x10);

        entries.push({
            id: buffer.readUint32LE(offset + 0x00),
            offsetStart: buffer.readUint32LE(offset + 0x04),
            sizeNeeded: pageAlign(buffer.readUint32LE(offset + 0x08), 4, 1),
            hash: buffer.readUint32LE(offset + 0x0C),
        });
    }

    return {
        buffer,
        size: buffer.length,
        offsetStart,
        count,
        entries
    }
};

/**
 * 
 * @param {Buffer} buffer 
 */
function createMasterTable(buffer) {
    if (buffer.length < 0x20) {
        console.log("[!] Error: Buffer too short to read master table.");

        process.exit(0);
    }

    return {
        data0: buffer.readUint32LE(0x00),
        data4: buffer.readUint32LE(0x04),
        offset: buffer.readUint32LE(0x08),
        elfSize: buffer.readUint32LE(0x0C),
        seed: buffer.readUint32LE(0x10),
        funcPass: buffer.readUint32LE(0x14),
        funcPassHex: FS.makeOffset(buffer.readUint32LE(0x14)),
        mprotSize: buffer.readUint32LE(0x18),
        elfSize2: buffer.readUint32LE(0x1C),
    }
};

/**
 * 
 * @param {Buffer} buffer 
 */
function readSubTable(buffer) {
    if (buffer.byteLength < 0x5C) {
        FS.hexdump(buffer);

        console.log("[!] Error: Buffer too short to read sub table.");

        process.exit(0);
    }

    return {
        elfType: buffer.readUint32LE(0x00),
        name: libNames[buffer.readUint32LE(0x00)] || "",
        processCheck: FS.makeOffset(buffer.readUint32LE(0x04)),
        skipProcess: (buffer.readUint32LE(0x04) & 2) != 0,
        useFuncPassoffs: (buffer.readUint32LE(0x04) & 0x100) == 0,
        process0x1000000: (buffer.readUint32LE(0x04) & 0x1000000) != 0,
        SliceTableOffset: buffer.readUint32LE(0x08),
        SliceTableOffsetHex: FS.makeOffset(buffer.readUint32LE(0x08)),
        SliceTableSize: buffer.readUint32LE(0x0C),
        ELFHeadersOffset: buffer.readUint32LE(0x10),
        ELFHeadersOffsetHex: FS.makeOffset(buffer.readUint32LE(0x10)),
        ELFHeadersSize: buffer.readUint32LE(0x14),
        elfType2: buffer.readUint32LE(0x18),
        offsetPassoffFunc: buffer.readUint32LE(0x1C),
        offsetPassoffFuncHex: FS.makeOffset(buffer.readUint32LE(0x1C)),
        offsetSetELFEntries: buffer.readUint32LE(0x20),
        offsetSetELFEntriesHex: FS.makeOffset(buffer.readUint32LE(0x20)),
        data24: buffer.readUint32LE(0x24),
        data28: buffer.readUint32LE(0x28),
        data2C: buffer.readUint32LE(0x2C),
        data30: buffer.readUint32LE(0x30),
        data34: buffer.readUint32LE(0x34),
        data38: buffer.readUint32LE(0x38),
        data3C: buffer.readUint32LE(0x3C),
        data40: buffer.readUint32LE(0x40),
        data44: buffer.readUint32LE(0x44),
        data48: buffer.readUint32LE(0x48),
        data4C: buffer.readUint32LE(0x4C),
        data50: buffer.readUint32LE(0x50),
        data54: buffer.readUint32LE(0x54),
        data58: buffer.readUint32LE(0x58),
    }
};

/**
 * 
 * @param {Buffer} buffer 
 * @returns {{str: Buffer, len: number}}
 */
function readCString(buffer, offset = 0) {
    // Find the index of the first null byte starting from the offset
    let i = 0;

    for (i = 0; buffer[offset + i]; i++) {
        ;
    }

    const str = buffer.subarray(offset, offset + i);

    return {
        str,
        len: str.length + 1
    }
}

/**
 * Current 32 bit
 * 
 * @param {Buffer} buffer 
 * @param {Buffer} MASTER_ELF_DATA 
 * @param {number} SHT_DYNAMICOffset 
 * @param {number} SHT_STRTAB 
 */
function parseData158_32(buffer, MASTER_ELF_DATA, SHT_DYNAMICOffset, SHT_STRTAB) {
    const offsetStart = 8;

    const finalData = {
        DTLinkOffset: buffer.readUint32LE(0x00) + offsetStart,
        DTLinkSize: buffer.readUint32LE(0x04),
        DynSymCount: buffer.readUint32LE(0x08),
        DynSymOffset: buffer.readUint32LE(0x0C) + offsetStart,
        IndexOffset: buffer.readUint32LE(0x10) + offsetStart,
        DynStrOffset: buffer.readUint32LE(0x14) + offsetStart,
    }

    var sizeTracker = 0;

    for (let i = 0; i < finalData.DynSymCount; i++) {
        const strData = readCString(buffer, finalData.DynStrOffset + sizeTracker);

        sizeTracker += strData.len;
 
        const IndexOffset = finalData.IndexOffset + (i * 4);

        const DynSymOffset = finalData.DynSymOffset + (i * 16);

        const index = buffer.readUint32LE(IndexOffset);

        const entry = {
            index: index,
            sym_name: buffer.readUint32LE(DynSymOffset + 0x00),
            sym_value: buffer.readUint32LE(DynSymOffset + 0x04),
            sym_size: buffer.readUint32LE(DynSymOffset + 0x08),
            sym_info: buffer.readUint8(DynSymOffset + 0x0C),
            sym_other: buffer.readUint8(DynSymOffset + 0x0D),
            sym_shndx: buffer.readUint16LE(DynSymOffset + 0x0E),
            nameBuffer: strData.str,
            name: strData.str.toString(),
        }

        if (entry.name == "__bss_start") {
            entry.sym_size = 4;
        }

        const entryStartOffset = SHT_DYNAMICOffset + (entry.index * 16);

        MASTER_ELF_DATA.writeUint32LE(entry.sym_name, entryStartOffset + 0x00);

        MASTER_ELF_DATA.writeUint32LE(entry.sym_value, entryStartOffset + 0x04);

        MASTER_ELF_DATA.writeUint32LE(entry.sym_size, entryStartOffset + 0x08);

        MASTER_ELF_DATA.writeUint8(entry.sym_info, entryStartOffset + 0x0C);

        MASTER_ELF_DATA.writeUint8(entry.sym_other, entryStartOffset + 0x0D);

        MASTER_ELF_DATA.writeUint16LE(entry.sym_shndx, entryStartOffset + 0x0E);

        var SHT_STRTABOffset = SHT_STRTAB + entry.sym_name;

        if(MASTER_ELF_DATA[SHT_STRTABOffset] == 0){
            for (let j = 0; j < entry.nameBuffer.length; j++) {
                MASTER_ELF_DATA[SHT_STRTABOffset++] = entry.nameBuffer[j];
            }
        }  
    }
};

/**
 * Current 64 bit
 * 
 * @param {Buffer} buffer 
 * @param {Buffer} MASTER_ELF_DATA 
 * @param {number} SHT_DYNAMICOffset 
 * @param {number} SHT_STRTAB 
 */
function parseData158_64(buffer, MASTER_ELF_DATA, SHT_DYNAMICOffset, SHT_STRTAB) {
    const offsetStart = 8;

    const finalData = {
        DTLinkOffset: buffer.readUint32LE(0x00) + offsetStart,
        DTLinkSize: buffer.readUint32LE(0x04),
        DynSymCount: buffer.readUint32LE(0x08),
        DynSymOffset: buffer.readUint32LE(0x0C) + offsetStart,
        IndexOffset: buffer.readUint32LE(0x10) + offsetStart,
        DynStrOffset: buffer.readUint32LE(0x14) + offsetStart,
    }

    var sizeTracker = 0;

    for (let i = 0; i < finalData.DynSymCount; i++) {
        const strData = readCString(buffer, finalData.DynStrOffset + sizeTracker);

        sizeTracker += strData.len;
 
        const IndexOffset = finalData.IndexOffset + (i * 4);

        const DynSymOffset = finalData.DynSymOffset + (i * 24);

        const index = buffer.readUint32LE(IndexOffset);

        const entry = {
            index: index,
            sym_name: buffer.readUint32LE(DynSymOffset + 0x00),
            sym_info: buffer.readUint8(DynSymOffset + 0x04),
            sym_other: buffer.readUint8(DynSymOffset + 0x05),
            sym_shndx: buffer.readUint16LE(DynSymOffset + 0x06),
            sym_value: buffer.readBigUInt64LE(DynSymOffset + 0x08),
            sym_size: buffer.readBigUInt64LE(DynSymOffset + 0x10),
            nameBuffer: strData.str,
            name: strData.str.toString(),
        }

        if (entry.name == "__bss_start") {
            entry.sym_size = 8n;
        }

        const entryStartOffset = SHT_DYNAMICOffset + (entry.index * 24);

        MASTER_ELF_DATA.writeUint32LE(entry.sym_name, entryStartOffset + 0x00);

        MASTER_ELF_DATA.writeUint8(entry.sym_info, entryStartOffset + 0x04);

        MASTER_ELF_DATA.writeUint8(entry.sym_other, entryStartOffset + 0x05);

        MASTER_ELF_DATA.writeUint16LE(entry.sym_shndx, entryStartOffset + 0x06);

        MASTER_ELF_DATA.writeBigUInt64LE(entry.sym_value, entryStartOffset + 0x08);

        MASTER_ELF_DATA.writeBigUInt64LE(entry.sym_size, entryStartOffset + 0x10);

        var SHT_STRTABOffset = SHT_STRTAB + entry.sym_name;

        if(MASTER_ELF_DATA[SHT_STRTABOffset] == 0){
            for (let j = 0; j < entry.nameBuffer.length; j++) {
                MASTER_ELF_DATA[SHT_STRTABOffset++] = entry.nameBuffer[j];
            }
        }  
    }
};

/**
 * Current 32 bit
 * 
 * @param {Buffer} buffer 
 */
function parse195(buffer) {
    const dstCount = buffer.readUint32LE(0x00);

    const dstOffset = buffer.readUint32LE(0x04);

    const entries = [];

    for (let i = 0; i < dstCount; i++) {
        const start = dstOffset + (i * 0x10);

        const dst = buffer.readInt32LE(start + 0x00);

        const srcOffset = buffer.readInt32LE(start + 0x08);

        const srcCount = buffer.readInt32LE(start + 0x0C);

        for (let z = 0; z < srcCount; z++) {
            const src = buffer.readInt8(srcOffset + (z * 0x08) + 0x00);

            const offset = buffer.readUint32LE(srcOffset + (z * 0x08) + 0x04);

            const entry = {
                /**
                 * Buffer to write to
                 */
                dst: dst,
                /**
                 * Offset within dst buffer
                 */
                offset: offset,
                /**
                 * Address buffer to add to the offset
                 */
                src: src
            }

            entries.push(entry);
        }
    }

    return entries;
};

/**
 * 3
 */
const memset32 = Buffer.from([
    0xF0, 0x0F, 0x2D, 0xE9, 0x1C, 0xB0, 0x8D, 0xE2, 0x10, 0xD0, 0x4D, 0xE2, 0x20, 0x00, 0x0B, 0xE5,
    0x01, 0xC0, 0xA0, 0xE1, 0x02, 0x30, 0xA0, 0xE1, 0x20, 0x50, 0x1B, 0xE5, 0x03, 0x10, 0xA0, 0xE3,
    0x05, 0x20, 0xA0, 0xE1, 0x02, 0x20, 0x01, 0xE0, 0x00, 0x00, 0x52, 0xE3, 0x10, 0x00, 0x00, 0x0A,
    0x03, 0x10, 0xA0, 0xE3, 0x05, 0x20, 0xA0, 0xE1, 0x02, 0x20, 0x01, 0xE0, 0x04, 0x40, 0x62, 0xE2,
    0x00, 0x00, 0x54, 0xE3, 0x0A, 0x00, 0x00, 0x0A, 0x04, 0x00, 0x53, 0xE1, 0x00, 0x00, 0x00, 0x2A,
    0x03, 0x40, 0xA0, 0xE1, 0x03, 0x30, 0x64, 0xE0, 0x03, 0x00, 0x00, 0xEA, 0x7C, 0x20, 0xEF, 0xE6,
    0x00, 0x20, 0xC5, 0xE5, 0x01, 0x50, 0x85, 0xE2, 0x01, 0x40, 0x44, 0xE2, 0x00, 0x00, 0x54, 0xE3,
    0xF9, 0xFF, 0xFF, 0x1A, 0x00, 0x00, 0x53, 0xE3, 0x26, 0x00, 0x00, 0x0A, 0x00, 0x80, 0xA0, 0xE3,
    0x00, 0x90, 0xA0, 0xE3, 0x7C, 0xA0, 0xEF, 0xE6, 0x24, 0xA0, 0x0B, 0xE5, 0x08, 0x40, 0xA0, 0xE3,
    0x13, 0x00, 0x00, 0xEA, 0x24, 0x60, 0x1B, 0xE5, 0x76, 0x60, 0xEF, 0xE6, 0x00, 0x70, 0xA0, 0xE3,
    0x06, 0x00, 0xA0, 0xE1, 0x07, 0x10, 0xA0, 0xE1, 0x1E, 0x22, 0x44, 0xE2, 0x82, 0x21, 0xA0, 0xE1,
    0x20, 0x70, 0x42, 0xE2, 0x28, 0x70, 0x0B, 0xE5, 0x20, 0xA0, 0x62, 0xE2, 0x2C, 0xA0, 0x0B, 0xE5,
    0x11, 0x72, 0xA0, 0xE1, 0x28, 0xA0, 0x1B, 0xE5, 0x10, 0x7A, 0x87, 0xE1, 0x2C, 0xA0, 0x1B, 0xE5,
    0x30, 0x7A, 0x87, 0xE1, 0x10, 0x62, 0xA0, 0xE1, 0x06, 0x80, 0x88, 0xE1, 0x07, 0x90, 0x89, 0xE1,
    0x01, 0x40, 0x44, 0xE2, 0x00, 0x00, 0x54, 0xE3, 0xE9, 0xFF, 0xFF, 0x1A, 0x05, 0x40, 0xA0, 0xE1,
    0xA3, 0x51, 0xA0, 0xE1, 0x85, 0x21, 0xA0, 0xE1, 0x03, 0x30, 0x62, 0xE0, 0x02, 0x00, 0x00, 0xEA,
    0xF0, 0x80, 0xC4, 0xE1, 0x08, 0x40, 0x84, 0xE2, 0x01, 0x50, 0x45, 0xE2, 0x00, 0x00, 0x55, 0xE3,
    0xFA, 0xFF, 0xFF, 0x1A, 0x04, 0x50, 0xA0, 0xE1, 0x03, 0x40, 0xA0, 0xE1, 0x03, 0x00, 0x00, 0xEA,
    0x7C, 0x30, 0xEF, 0xE6, 0x00, 0x30, 0xC5, 0xE5, 0x01, 0x50, 0x85, 0xE2, 0x01, 0x40, 0x44, 0xE2,
    0x00, 0x00, 0x54, 0xE3, 0xF9, 0xFF, 0xFF, 0x1A, 0x20, 0x30, 0x1B, 0xE5, 0x03, 0x00, 0xA0, 0xE1,
    0x1C, 0xD0, 0x4B, 0xE2, 0xF0, 0x0F, 0xBD, 0xE8, 0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0x00, 0x00,
]);

/**
 * 4
 */
const strcat32 = Buffer.from([
    0x70, 0x08, 0x2D, 0xE9, 0x0C, 0xB0, 0x8D, 0xE2, 0x08, 0xD0, 0x4D, 0xE2, 0x10, 0x00, 0x0B, 0xE5,
    0x14, 0x10, 0x0B, 0xE5, 0x10, 0x40, 0x1B, 0xE5, 0x14, 0x50, 0x1B, 0xE5, 0x00, 0x00, 0x00, 0xEA,
    0x01, 0x40, 0x84, 0xE2, 0x00, 0x30, 0xD4, 0xE5, 0x00, 0x00, 0x53, 0xE3, 0xFB, 0xFF, 0xFF, 0x1A,
    0x00, 0x60, 0xD5, 0xE5, 0x06, 0x30, 0xA0, 0xE1, 0x00, 0x30, 0xC4, 0xE5, 0x00, 0x00, 0x56, 0xE3,
    0x00, 0x00, 0x00, 0x1A, 0x02, 0x00, 0x00, 0xEA, 0x01, 0x40, 0x84, 0xE2, 0x01, 0x50, 0x85, 0xE2,
    0xF6, 0xFF, 0xFF, 0xEA, 0x10, 0x30, 0x1B, 0xE5, 0x03, 0x00, 0xA0, 0xE1, 0x0C, 0xD0, 0x4B, 0xE2,
    0x70, 0x08, 0xBD, 0xE8, 0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

/**
 * 5
 */
const strchr32 = Buffer.from([
    0x04, 0xB0, 0x2D, 0xE5, 0x00, 0xB0, 0x8D, 0xE2, 0x00, 0x30, 0xA0, 0xE1, 0x01, 0x20, 0xA0, 0xE1,
    0x00, 0x10, 0xD3, 0xE5, 0x02, 0x00, 0x51, 0xE1, 0x00, 0x00, 0x00, 0x1A, 0x07, 0x00, 0x00, 0xEA,
    0x00, 0x10, 0xD3, 0xE5, 0x00, 0x00, 0x51, 0xE3, 0x02, 0x00, 0x00, 0x1A, 0x00, 0x00, 0xA0, 0xE1,
    0x00, 0x30, 0xA0, 0xE3, 0x01, 0x00, 0x00, 0xEA, 0x01, 0x30, 0x83, 0xE2, 0xF3, 0xFF, 0xFF, 0xEA,
    0x03, 0x00, 0xA0, 0xE1, 0x00, 0xD0, 0x4B, 0xE2, 0x04, 0xB0, 0x9D, 0xE4, 0x1E, 0xFF, 0x2F, 0xE1,
]);

/**
 * 6
 */
const strcmp32 = Buffer.from([
    0x10, 0x08, 0x2D, 0xE9, 0x04, 0xB0, 0x8D, 0xE2, 0x00, 0x20, 0xA0, 0xE1, 0x01, 0x30, 0xA0, 0xE1,
    0x00, 0x40, 0xD2, 0xE5, 0x00, 0x10, 0xD3, 0xE5, 0x04, 0x00, 0x51, 0xE1, 0x06, 0x00, 0x00, 0x0A,
    0x00, 0x30, 0xD3, 0xE5, 0x04, 0x00, 0x53, 0xE1, 0x01, 0x00, 0x00, 0x2A, 0x01, 0x30, 0xA0, 0xE3,
    0x00, 0x00, 0x00, 0xEA, 0x00, 0x30, 0xE0, 0xE3, 0x07, 0x00, 0x00, 0xEA, 0x00, 0x00, 0x54, 0xE3,
    0x02, 0x00, 0x00, 0x1A, 0x00, 0x00, 0xA0, 0xE1, 0x00, 0x30, 0xA0, 0xE3, 0x02, 0x00, 0x00, 0xEA,
    0x01, 0x20, 0x82, 0xE2, 0x01, 0x30, 0x83, 0xE2, 0xEC, 0xFF, 0xFF, 0xEA, 0x03, 0x00, 0xA0, 0xE1,
    0x04, 0xD0, 0x4B, 0xE2, 0x10, 0x08, 0xBD, 0xE8, 0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0x00, 0x00,
]);

/**
 * 7
 */
const strcpy32 = Buffer.from([
    0x70, 0x08, 0x2D, 0xE9, 0x0C, 0xB0, 0x8D, 0xE2, 0x08, 0xD0, 0x4D, 0xE2, 0x10, 0x00, 0x0B, 0xE5,
    0x14, 0x10, 0x0B, 0xE5, 0x10, 0x50, 0x1B, 0xE5, 0x14, 0x40, 0x1B, 0xE5, 0x00, 0x60, 0xD4, 0xE5,
    0x06, 0x30, 0xA0, 0xE1, 0x00, 0x30, 0xC5, 0xE5, 0x00, 0x00, 0x56, 0xE3, 0x00, 0x00, 0x00, 0x1A,
    0x02, 0x00, 0x00, 0xEA, 0x01, 0x50, 0x85, 0xE2, 0x01, 0x40, 0x84, 0xE2, 0xF6, 0xFF, 0xFF, 0xEA,
    0x10, 0x30, 0x1B, 0xE5, 0x03, 0x00, 0xA0, 0xE1, 0x0C, 0xD0, 0x4B, 0xE2, 0x70, 0x08, 0xBD, 0xE8,
    0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

/**
 * 8
 */
const strlen32 = Buffer.from([
    0x10, 0x08, 0x2D, 0xE9, 0x04, 0xB0, 0x8D, 0xE2, 0x00, 0x30, 0xA0, 0xE1, 0x03, 0x40, 0xA0, 0xE1,
    0x00, 0x00, 0x00, 0xEA, 0x01, 0x30, 0x83, 0xE2, 0x00, 0x20, 0xD3, 0xE5, 0x00, 0x00, 0x52, 0xE3,
    0xFB, 0xFF, 0xFF, 0x1A, 0x03, 0x20, 0xA0, 0xE1, 0x04, 0x30, 0xA0, 0xE1, 0x02, 0x30, 0x63, 0xE0,
    0x03, 0x00, 0xA0, 0xE1, 0x04, 0xD0, 0x4B, 0xE2, 0x10, 0x08, 0xBD, 0xE8, 0x1E, 0xFF, 0x2F, 0xE1,
]);

function getSHTEntry32() {
    return Buffer.from([
        0x00, 0x00, 0x00, 0x00, // 0x00 - s_name
        0x01, 0x00, 0x00, 0x00, // 0x04 - s_type
        0x00, 0x00, 0x00, 0x00, // 0x08 - s_flags
        0x00, 0x00, 0x00, 0x00, // 0x0C - s_addr*
        0x00, 0x00, 0x00, 0x00, // 0x10 - s_offset*
        0x00, 0x00, 0x00, 0x00, // 0x14 - s_size*
        0x00, 0x00, 0x00, 0x00, // 0x18 - s_link
        0x00, 0x00, 0x00, 0x00, // 0x1C - s_info
        0x04, 0x00, 0x00, 0x00, // 0x20 - a_addralign
        0x00, 0x00, 0x00, 0x00, // 0x24 - s_entsize
    ]);
};

function getSHTEntry64() {
    return Buffer.from([
        0x00, 0x00, 0x00, 0x00, // 0x00 - s_name
        0x01, 0x00, 0x00, 0x00, // 0x04 - s_type
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08 - s_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x10 - s_addr*
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x18 - s_offset*
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20 - s_size*
        0x00, 0x00, 0x00, 0x00, // 0x28 - s_link
        0x00, 0x00, 0x00, 0x00, // 0x2C - s_info
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x30 - a_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x38 - s_entsize
    ]);
};

/**
 * 
 * @param {number} dataOffset 
 * @param {{start:number, size: number}[]} splits 
 * @param {number} memoryStart 
 */
function makeSHTEntries32(dataOffset, splits, memoryStart = 0x6000000) {
    var entryMemoryStart = memoryStart;

    const buffers = [];

    const meta = [];

    for (let i = 0; i < splits.length; i++) {
        const el = splits[i];

        const s_addr = entryMemoryStart;

        const s_offset = dataOffset + el.start;

        const s_size = el.size;

        meta.push(
            {
                /**
                 * Memory addres
                 */
                s_addr,
                /**
                 * Offset within the file
                 */
                s_offset
            }
        );

        entryMemoryStart = pageAlign(entryMemoryStart + el.size, 16, 1);

        const entry = getSHTEntry32();

        entry.writeUint32LE(s_addr, 0x0C);

        entry.writeUint32LE(s_offset, 0x10);

        entry.writeUint32LE(s_size, 0x14);

        buffers.push(entry);
    }

    return {
        buffer: Buffer.concat(buffers),
        meta
    }
};

const py_replace1 = `import ida_name
import ida_funcs
import ida_kernwin

base = ida_nalt.get_imagebase()

def rename_jump_slot(r_offset, func_name):
    got_ea = base + r_offset

    ida_name.set_name(
        got_ea,
        f"{func_name}_got",
        ida_name.SN_FORCE
    )

    plt_ea = ida_bytes.get_dword(got_ea)

    if ida_funcs.get_func(plt_ea):
        ida_name.set_name(
            plt_ea,
            f"{func_name}_plt",
            ida_name.SN_FORCE
        )

def rename_glob_dat(r_offset, func_name):
    got_ea = base + r_offset

    ida_name.set_name(
        got_ea,
        f"{func_name}_got",
        ida_name.SN_FORCE
    )

REL = {\n`;

const py_replace2 = `\n}

JMPREL = {\n`;

const py_replace3 = `\n}

for ea, new_name in REL.items():
	rename_glob_dat(ea, new_name)

for ea, new_name in JMPREL.items():
	rename_jump_slot(ea, new_name)

print("Done")`;

/**
 * 
 * @param {{offset: number, name: string}[]} REL 
 * @param {{offset: number, name: string}[]} JMPREL 
 * @param {number} min 
 * @param {number} diff 
 */
function makePythonReplacementScript(REL, JMPREL, min, diff) {
    const RELEntries = [];

    for (let i = 0; i < REL.length; i++) {
        const el = REL[i];

        var off = el.offset;

        if(off >= min){
            off += diff;
        }

        const entry = `    ${FS.makeOffset(off)}: "${el.name}",`;

        RELEntries.push(entry);
    }

    const JMPRELEntries = [];

    for (let i = 0; i < JMPREL.length; i++) {
        const el = JMPREL[i];

        var off = el.offset;

        if(off >= min){
            off += diff;
        }

        const entry = `    ${FS.makeOffset(off)}: "${el.name}",`;

        JMPRELEntries.push(entry);
    }

    return py_replace1 + RELEntries.join("\n") + py_replace2 + JMPRELEntries.join("\n") + py_replace3;
};

/**
 * 
 * @param {Buffer} buffer 
 */
function parse157Headers32(buffer) {
    const STROFF = buffer.readUint32LE(0x10);

    const SYMOFF = buffer.readUint32LE(0x18);

    const SYMCOUNT = buffer.readUint32LE(0x1C);

    const RELOFF = buffer.readUint32LE(0x20);

    const RELCOUNT = buffer.readUint32LE(0x24);

    const JMPRELOFF = buffer.readUint32LE(0x28);

    const JMPRELCOUNT = buffer.readUint32LE(0x2C);

    const strs = [];

    for (let i = 0; i < SYMCOUNT; i++) {
        const entry = SYMOFF + (i * 0x10);

        const off = buffer.readUint32LE(entry);

        let z = 0;

        for (z = 0; buffer[(STROFF + off) + z]; z++) {
            ;
        }

        strs.push(buffer.subarray(STROFF + off, (STROFF + off) + z).toString());
    }

    /**
     * @type {{offset: number, name: string}[]}
     */
    const REL = [];

    for (let i = 0; i < RELCOUNT; i++) {
        const entry = RELOFF + (i * 0x8);

        const offset = buffer.readUint32LE(entry);

        const type = buffer[entry + 0x4];

        const index = buffer[entry + 0x5] | (buffer[entry + 0x6] << 8) | (buffer[entry + 0x7] << 16);

        if (type == 0x15 && index != 0) {
            REL.push({
                offset: offset,
                name: strs[index]
            });
        }
    }

    /**
     * @type {{offset: number, name: string}[]}
     */
    const JMPREL = [];

    for (let i = 0; i < JMPRELCOUNT; i++) {
        const entry = JMPRELOFF + (i * 0x8);

        const offset = buffer.readUint32LE(entry);

        const type = buffer[entry + 0x4];

        const index = buffer[entry + 0x5] | (buffer[entry + 0x6] << 8) | (buffer[entry + 0x7] << 16);

        if (type == 0x16 && index != 0) {
            JMPREL.push({
                offset: offset,
                name: strs[index]
            });
        }
    }

    return { REL, JMPREL };
};

/**
 * 
 * @param {Buffer} buffer 
 */
function parse157Headers64(buffer) {
    const STROFF = buffer.readUint32LE(0x10);

    const SYMOFF = buffer.readUint32LE(0x18);

    const SYMCOUNT = buffer.readUint32LE(0x1C);

    const RELOFF = buffer.readUint32LE(0x20);

    const RELCOUNT = buffer.readUint32LE(0x24);

    const JMPRELOFF = buffer.readUint32LE(0x28);

    const JMPRELCOUNT = buffer.readUint32LE(0x2C);

    const strs = [];

    for (let i = 0; i < SYMCOUNT; i++) {
        const entry = SYMOFF + (i * 0x18);

        const off = buffer.readUint32LE(entry);

        let z = 0;

        for (z = 0; buffer[(STROFF + off) + z]; z++) {
            ;
        }

        strs.push(buffer.subarray(STROFF + off, (STROFF + off) + z).toString());
    }

    /**
     * @type {{offset: number, name: string}[]}
     */
    const REL = [];

    for (let i = 0; i < RELCOUNT; i++) {
        const entry = RELOFF + (i * 0x18);

        const offset = buffer.readBigUInt64LE(entry);

        const type = buffer.readUint32LE(entry + 0x8);

        const index = buffer.readUint32LE(entry + 0xC);

        if (type == 0x401 && index != 0) {
            REL.push({
                offset: Number(offset),
                name: strs[index]
            });
        }
    }

    /**
     * @type {{offset: number, name: string}[]}
     */
    const JMPREL = [];

    for (let i = 0; i < JMPRELCOUNT; i++) {
        const entry = JMPRELOFF + (i * 0x18);

        const offset = buffer.readBigUInt64LE(entry);

        const type = buffer.readUint32LE(entry + 0x8);

        const index = buffer.readUint32LE(entry + 0xC);

        if (type == 0x402 && index != 0) {
            JMPREL.push({
                offset: Number(offset),
                name: strs[index]
            });
        }
    }

    return { REL, JMPREL };
};

/**
 * 
 * @param {Buffer} buffer 
 * @param {{offset: number, name: string}[]} array
 */
function parse185(buffer, array) {
    const count = buffer.length >> 3;

    for (let i = 0; i < count; i++) {
        const entry = i * 8;

        const type = buffer.readUint32LE(entry);

        const offset = buffer.readUint32LE(entry + 4);

        var name = "";

        switch (type) {
            case 3:
                name = "memset";
                break;
            case 4:
                name = "strcat";
                break;
            case 5:
                name = "strchr";
                break;
            case 6:
                name = "strcmp";
                break;
            case 7:
                name = "strcpy";
                break;
            case 8:
                name = "strlen";
                break;
            default:
                break;
        }

        array.push({ offset: offset, name: name });
    }
}

module.exports = {
    createMasterTable,
    libNamesLegacy,
    libNames,
    LV_ENTRY_SIZE,
    readLvInfo,
    TABLE_ENTRY_SIZE,
    readTableEntry,
    readMasterChunk,
    parseELFSymbolAndString32,
    read241,
    readSHT_LOUSER32,
    readSHT_LOUSER64,
    readSHT_LOUSER32_SIZE,
    readSHT_LOUSER64_SIZE,
    readSubTable,
    readData1Entries,
    getSHT_DYNAMICAddress32,
    getSHT_DYNAMICAddress64,
    getSHT_DYNAMICSize32,
    getSHT_DYNAMICSize64,
    getSHT_STRTABAddress32,
    getSHT_STRTABAddress64,
    parseData158_32,
    parseData158_64,
    parse195,
    makePythonReplacementScript,
    parse157Headers32,
    parse157Headers64,
    parse185,
    getSHTEndOffset32,
    getSHTEndOffset64,
    makeSHTEntries32,
    fixData32_SIZE,
    fixData64_SIZE,
};