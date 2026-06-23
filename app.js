// @ts-check

const pack = require('./package.json');
const path = require("path");
const { FS } = require("./src/File");
const { 
    Command, 
    Option 
} = require('commander');
const { 
    readLvInfo,
    readTableEntry,
    parseELFSymbolAndString32,
    read241,
    readSHT_LOUSER32,
    readSHT_LOUSER64,
    readSHT_LOUSER32_SIZE,
    readSHT_LOUSER64_SIZE,
    getSHT_DYNAMICAddress32,
    getSHT_DYNAMICAddress64,
    getSHT_DYNAMICSize32,
    getSHT_DYNAMICSize64,
    getSHT_STRTABAddress32,
    getSHT_STRTABAddress64,
    parseData158_32,
    parseData158_64,
    parse157Headers32,
    parse157Headers64,
    makePythonReplacementScript,
    parse185,
    parse195,
    getSHTEndOffset32,
    getSHTEndOffset64,
    fixData32_SIZE,
    fixData64_SIZE,
    libNames
} = require("./src/Structures");
const {
    DecodeMasterTable,
    PRNG_MASTER,
    decodeELF,
    decodeSeedMaster,
    decodeSeedSub,
    decodeSubTableMaster,
    decodeSubTableSub,
    decodeNextLvMaster,
    decodeNextLvSub,
    decodeSubTable157,
    pageAlign,
    decodeData1Headers,
    readData1Entry,
    DoDecodeString,
    DoDecodeString2
} = require('./src/Decode');

/**
 * How the app parses arguments passed to it at the command line level.
 * 
 * @class
 */
const PROGRAM = new Command();

const hasFile = new Option('-f, --file <string>', 'Location of the library file');

//hasFile.required = true; hasFile.mandatory = true;

const data1 = new Option('-d, --data1', 'The input file is a data1.dat file for decoding');

const data1ID = new Option('-i, --id [string...]', 'Array of data1.dat entry ids to match with seeds');

const data1Seeds = new Option('-s, --seeds [string...]', 'Array of data1.dat seeds to match with ids (can be in hex or decimal)');

const hasOutput = new Option('-o, --output <string>', 'Location of for the decompiled library files (defaults to input folder)');

const legacy = new Option('-y, --legacy', 'For libraries older than 2020 (only 32 bit), try running legacy mode if decode failed.'); 

const decodeString = new Option('-r, --decodestring [string...]', 'Hex strings to decode (use the --legacy for legacy coded strings)'); 

legacy.defaultValue = false;

const LOUSER_START = new Option('-l, --LOUSER_START <string>', 'Offset within the LOUSER data of the master library to start (default 572)');

LOUSER_START.defaultValue = 572;

const aes_table0 = new Option('-e0, --aes_table0 <string>', 'Offset within the libLv0.so created to the encryption table. Can be in hex or decimal.');

const seed0 = new Option('-s0, --seed0 <string>','Offset within the libLv0.so to the seed value used in decoding the next level. (can be in hex or decimal)');

const aes_table1 = new Option('-e1, --aes_table1 <string>', 'Offset within the libLv1.so created to the encryption table. Can be in hex or decimal.');

const seed1 = new Option('-s1, --seed1 <string>','Offset within the libLv1.so to the seed value used in decoding the next level. (can be in hex or decimal)');

const aes_table2 = new Option('-e2, --aes_table2 <string>', 'Offset within the libLv2.so created to the encryption table. Can be in hex or decimal.');

const seed2 = new Option('-s2, --seed2 <string>','Offset within the libLv2.so to the seed value used in decoding the next level. (can be in hex or decimal)');

const aes_table3 = new Option('-e3, --aes_table3 <string>', 'Offset within the libLv3.so created to the encryption table. Can be in hex or decimal.');

const seed3 = new Option('-s3, --seed3 <string>','Offset within the libLv3.so to the seed value used in decoding the next level. (can be in hex or decimal)');

const aes_table4 = new Option('-e4, --aes_table4 <string>', 'Offset within the libLv4.so created to the encryption table. Can be in hex or decimal.');

const seed4 = new Option('-s4, --seed4 <string>','Offset within the libLv4.so to the seed value used in decoding the next level. (can be in hex or decimal)');

const aes_table5 = new Option('-e5, --aes_table5 <string>', 'Offset within the libLv5.so created to the encryption table. Can be in hex or decimal.');

const seed5 = new Option('-s5, --seed5 <string>','Offset within the libLv5.so to the seed value used in decoding the next level. (can be in hex or decimal)');

const aes_table6 = new Option('-e6, --aes_table6 <string>', 'Offset within the libLv6.so created to the encryption table. Can be in hex or decimal.');

const seed6 = new Option('-s6, --seed6 <string>','Offset within the libLv6.so to the seed value used in creating the master library. (can be in hex or decimal)');

const seed_table6 = new Option('-t6, --seed_table6 <string>','Offset within the libLv6.so to the seed value used in creating the tables for the master library. (can be in hex or decimal)');

const offsets6 = new Option('-o6, --offsets6 <string>','Offset within the libLv6.so to the count of offset sections used in creating the master library jump tables (only in 32 bit libraries). (can be in hex or decimal)');

const aes_table7 = new Option('-e7, --aes_table7 <string>', 'Offset within the libLv6.so created to the encryption table. Can be in hex or decimal.');

const seed7 = new Option('-s7, --seed7 <string>','Offset within the libLv6.so to the seed value used in decoding the next level. (can be in hex or decimal)');

// #region Legacy options

const hasLv0 = new Option('-0, --Lv0 <string>', 'The location of the Lv0 structure within the file. (can be in hex or decimal)');

hasLv0.defaultValue = 0;

const hasLv1 = new Option('-1, --Lv1 <string>', 'The location of the Lv1 structure within the last library created. (can be in hex or decimal)');

const hasLv2 = new Option('-2, --Lv2 <string>', 'The location of the Lv2 structure within the last library created. (can be in hex or decimal)');

const hasLv3 = new Option('-3, --Lv3 <string>', 'The location of the Lv3 structure within the last library created. (can be in hex or decimal)');
// Set commands to program for
PROGRAM
    .name('ht_decoder')
    .description(`\x1b[36mFor decompiling Android libraries\x1b[0m`)
    .version(pack.version)
    .addOption(hasFile)
    .addOption(data1)
    .addOption(data1ID)
    .addOption(data1Seeds)
    .addOption(hasOutput)
    .addOption(legacy)
    .addOption(LOUSER_START)
    .addOption(aes_table0)
    .addOption(seed0)
    .addOption(aes_table1)
    .addOption(seed1)
    .addOption(aes_table2)
    .addOption(seed2)
    .addOption(aes_table3)
    .addOption(seed3)
    .addOption(aes_table4)
    .addOption(seed4)
    .addOption(aes_table5)
    .addOption(seed5)
    .addOption(aes_table6)
    .addOption(seed6)
    .addOption(seed_table6)
    .addOption(offsets6)
    .addOption(aes_table7)
    .addOption(seed7)
    .addOption(hasLv0)
    .addOption(hasLv1)
    .addOption(hasLv2)
    .addOption(hasLv3)
    .addOption(decodeString);

PROGRAM.parse(process.argv);

/**
 * Command line arguments.
 */
const ARGV = PROGRAM.opts();

/**
 * Converts string to number
 * 
 * @param {string|number} str
 */
function _parseNumber(str) {
    if(typeof str == "number"){
        return str;
    }

    if(typeof str == "string"){
        if (str[0] == "0" && str[1] == "x") { // hex
            return parseInt(str, 16);
        }

        return parseInt(str, 10);
    }

    return str;
};

/**
 * Base path where server is running.
 * 
 * @returns {string} directory name
 */
function _init_dir_name() {
    // @ts-ignore
    if (process.pkg) {
        return path.dirname(process.execPath);
    } else {
        return process.cwd();
    }
};

if(ARGV.decodestring){
    if(ARGV.legacy){
        try {
            for (let i = 0; i < ARGV.decodestring.length; i++) {
                const str = ARGV.decodestring[i];

                var buffer = Buffer.from(str,"hex");

                const len = pageAlign(buffer.length, 4, 1);

                if(len != buffer.length){
                    const destBuf = Buffer.alloc(len);

                    buffer.copy(destBuf, 0);
                }

                console.log(DoDecodeString(buffer));
            }

            process.exit(0);
        } catch (error) {
            console.log(error);

            process.exit(0);
        }
    } else {
        try {
            for (let i = 0; i < ARGV.decodestring.length; i++) {
                const str = ARGV.decodestring[i];

                var buffer = Buffer.from(str,"hex");

                const len = pageAlign(buffer.length, 4, 1);

                if(len != buffer.length){
                    const destBuf = Buffer.alloc(len);

                    buffer.copy(destBuf, 0);
                }

                console.log(DoDecodeString2(buffer));
            }

            process.exit(0);
        } catch (error) {
            console.log(error);

            process.exit(0);
        }
    }
}

const DIR_NAME = _init_dir_name();

var INPUT_LIB_PATH = "";

var INPUT_LIB_NAME = "";

// get file path
try {
    if (!FS.fileExists(ARGV.file)) {
        if (path.isAbsolute(ARGV.file)) {
            console.log(`[!] Error: Can't find file ${ARGV.file}`);

            process.exit(0);
        }

        const homePath = path.join(DIR_NAME, ARGV.file);

        if (!FS.fileExists(homePath)) {
            console.log(`[!] Error: Can't find file ${homePath}`);

            process.exit(0);
        }

        INPUT_LIB_PATH = homePath;
    } else {
        INPUT_LIB_PATH = ARGV.file;

        INPUT_LIB_NAME = path.parse(INPUT_LIB_PATH).name;
    }
} catch (error) {
    // @ts-ignore
    console.log(error);

    process.exit(0);
} 

var OUTPUT_PATH = "";

try {
    if(ARGV.output == undefined){
        OUTPUT_PATH = path.dirname(INPUT_LIB_PATH);
    } else {
        if (!FS.directoryExists(ARGV.output)) {
            if (path.isAbsolute(ARGV.output)) {
                console.log(`[!] Error: Can't find file ${ARGV.output}`);

                process.exit(0);
            }

            const homePath = path.join(DIR_NAME, ARGV.output);

            if (!FS.directoryExists(homePath)) {
                console.log("[*] Created output folder: " + homePath);

                FS.createDirectory(homePath);
            }

            OUTPUT_PATH = homePath;
        } else {
            FS.createDirectory(ARGV.output);

            OUTPUT_PATH = ARGV.output;
        }
    }
} catch (error) {
    console.log(error);

    process.exit(0);
}

/**
 * @type {number[]}
 */
const LvInfos = [];

LvInfos.push(_parseNumber(ARGV.Lv0));

if (ARGV.Lv1) {
    LvInfos.push(_parseNumber(ARGV.Lv1));
}

if (ARGV.Lv2 && !ARGV.Lv1) {
    console.log(`[!] Error: Can't have Lv2 without Lv1 offset.`);

    process.exit(0);
}

if (ARGV.Lv2) {
    LvInfos.push(_parseNumber(ARGV.Lv2));
}

if (ARGV.Lv3 && !ARGV.Lv2) {
    console.log(`[!] Error: Can't have Lv3 without Lv2 offset.`);

    process.exit(0);
}

if (ARGV.Lv3) {
    LvInfos.push(_parseNumber(ARGV.Lv3));
}

ARGV.LOUSER_START = _parseNumber(ARGV.LOUSER_START);

ARGV.seed0 = _parseNumber(ARGV.seed0);

ARGV.aes_table0 = _parseNumber(ARGV.aes_table0);

ARGV.seed1 = _parseNumber(ARGV.seed1);

ARGV.aes_table1 = _parseNumber(ARGV.aes_table1);

ARGV.seed2 = _parseNumber(ARGV.seed2);

ARGV.aes_table2 = _parseNumber(ARGV.aes_table2);

ARGV.seed3 = _parseNumber(ARGV.seed3);

ARGV.aes_table3 = _parseNumber(ARGV.aes_table3);

ARGV.seed4 = _parseNumber(ARGV.seed4);

ARGV.aes_table4 = _parseNumber(ARGV.aes_table4);

ARGV.seed5 = _parseNumber(ARGV.seed5);

ARGV.aes_table5 = _parseNumber(ARGV.aes_table5);

ARGV.seed6 = _parseNumber(ARGV.seed6);

ARGV.aes_table6 = _parseNumber(ARGV.aes_table6);

ARGV.seed_table6 = _parseNumber(ARGV.seed_table6);

ARGV.offsets6 = _parseNumber(ARGV.offsets6);

ARGV.seed7 = _parseNumber(ARGV.seed7);

ARGV.aes_table7 = _parseNumber(ARGV.aes_table7);

// #region Code Starts

/**
 * @type {Buffer<ArrayBufferLike>}
 */
var MASTER_ELF_DATA;

try {
    MASTER_ELF_DATA = FS.readFile(INPUT_LIB_PATH);
} catch (error) {
    console.log(error);

    process.exit(0);
}

const is32bit = MASTER_ELF_DATA[4] == 1 ? true : false;

const isLE = MASTER_ELF_DATA[5] == 1? true : false;

if(!isLE){
    console.log(`[!] Error: Lib is Big Endian. Not an Android lib.`);

    process.exit(0);
}

const isARM32 = MASTER_ELF_DATA.readUint16LE(0x12) == 0x28;

const LOUSEROffset = isARM32 ? readSHT_LOUSER32(MASTER_ELF_DATA) : readSHT_LOUSER64(MASTER_ELF_DATA);

const LOUSER_SIZE = isARM32 ? readSHT_LOUSER32_SIZE(MASTER_ELF_DATA) : readSHT_LOUSER64_SIZE(MASTER_ELF_DATA);

const SHT_DYNAMICOffset = isARM32 ? getSHT_DYNAMICAddress32(MASTER_ELF_DATA) : getSHT_DYNAMICAddress64(MASTER_ELF_DATA);

const SHT_DYNAMIC_SIZE = isARM32 ? getSHT_DYNAMICSize32(MASTER_ELF_DATA) : getSHT_DYNAMICSize64(MASTER_ELF_DATA);

const SHT_STRTAB = isARM32 ? getSHT_STRTABAddress32(MASTER_ELF_DATA) : getSHT_STRTABAddress64(MASTER_ELF_DATA);

const SHTEndOffset = isARM32 ? getSHTEndOffset32(MASTER_ELF_DATA) : getSHTEndOffset64(MASTER_ELF_DATA);

console.log("[+] Lib:", INPUT_LIB_NAME);

console.log(isARM32 ? "[+] Processor: arm" : "[+] Processor: arm64");

LOUSEROffset ? console.log("[+] LOUSER: has offset", FS.makeOffset(LOUSEROffset)) : console.log("[-] LOUSER: not found!");

function runLegacy(){
    /**
     * @type {Buffer}
     */
    var LAST_ELF;

    /**
     * @type {Buffer}
     */
    var CURRENT_ELF;

    var completeled = false;

    /**
     * @type {Buffer}
     */
    var type241;

    /**
     * @type {Buffer}
     */
    var type248;

    for (let i = 0; i < LvInfos.length; i++) {
        const LvInfo = LvInfos[i];

        if(i == 0){
            CURRENT_ELF = MASTER_ELF_DATA;
        } else {
            // @ts-ignore
            CURRENT_ELF = LAST_ELF;
        }

        if(LvInfo > CURRENT_ELF.byteLength){
            console.log(`[!] Error: Lv${i} info outside of data size. ${LvInfo} > ${CURRENT_ELF.byteLength}`);

            process.exit(0);
        }

        const LvData = readLvInfo(CURRENT_ELF, LvInfo);

        console.log(`[+] Lv${i}`, LvData);

        if(LvData.NextLvInfo != LvInfo){
            console.log("[!] Warning: LvInfo didn't pass check.");
        }

        var masterLibName = `${INPUT_LIB_NAME}_Lv${i}_${LvData.masterElfSize}.so`;

        const ElfChunk = MASTER_ELF_DATA.subarray(
            LOUSEROffset + LvData.elfchunkOffset, 
            LOUSEROffset + LvData.elfchunkOffset + LvData.elfchunkSize
        );

        const CONTROLLER_ELF_BUFFER = Buffer.alloc(LvData.masterElfSize);

        decodeELF(ElfChunk, CONTROLLER_ELF_BUFFER);

        console.log(`[+] Creating ${masterLibName}`);

        FS.writeFile(CONTROLLER_ELF_BUFFER, path.join(OUTPUT_PATH, masterLibName));
        // now tables
        for (let z = 0; z < (LvData.tableSize / 0x38) >>> 0; z++) {
            const off = LOUSEROffset + LvData.tableOffset + (z * 0x38);

            const tableData = readTableEntry(MASTER_ELF_DATA, off);

            console.log(`[+] Table${i}`, tableData);

            var libTableName = tableData.name;

            if(tableData.name == ""){
                libTableName = `${INPUT_LIB_NAME}_Lv${i}_type${tableData.type}_${tableData.offsetWithinMaster}.so`;
            }

            const chunktable = MASTER_ELF_DATA.subarray(
                LOUSEROffset + tableData.offsetWithinMaster, 
                LOUSEROffset + tableData.offsetWithinMaster + tableData.sizeWithinMaster);

            var dstTable = Buffer.alloc(tableData.distSize);

            decodeELF(chunktable, dstTable);

            if(tableData.type == 241){
                type241 = dstTable;
            }

            if(tableData.type == 248){
                type248 = dstTable;
            }

            console.log(`[+] Creating ${libTableName}`);

            FS.writeFile(dstTable, path.join(OUTPUT_PATH, libTableName));
            // @ts-ignore
            if(type248 != undefined && type241 != undefined){
                completeled = true;
            }
        }

        LAST_ELF = CONTROLLER_ELF_BUFFER;
    }

    if(completeled){
        const offsets = parseELFSymbolAndString32(MASTER_ELF_DATA);
        // @ts-ignore
        const replacementData = read241(type241);

        replacementData.symbolData.copy(MASTER_ELF_DATA, offsets.DT_SYMTAB, 0);

        replacementData.stringData.copy(MASTER_ELF_DATA, offsets.DT_STRTAB, 0);
        // @ts-ignore
        decodeELF(type248, MASTER_ELF_DATA);

        try {
            FS.writeFile(MASTER_ELF_DATA, path.join(OUTPUT_PATH, INPUT_LIB_NAME + "_decrypted.so"));

            console.log(`[+] Created ${INPUT_LIB_NAME + "_decrypted.so"}`);
        } catch (error) {
            console.log(error);

            process.exit(0);
        }
    }
};

if(ARGV.data1){
    if(ARGV.id.length != ARGV.seeds.length){
        console.log("[!] Error: When parsing data1.dat, the id array must match the seed array length for pairing.");

        process.exit(0);
    }

    console.log("[*] Decoding data1.dat.");

    /**
     * @type {{[key: string]: number}}
     */
    const idSeeds = {};

    for (let index = 0; index < ARGV.id.length; index++) {
        const el = ARGV.id[index];

        idSeeds[el] = _parseNumber(ARGV.seeds[index]);
    }

    const masterData = decodeData1Headers(MASTER_ELF_DATA);

    for (let i = 0; i < masterData.entries.length; i++) {
        const element = masterData.entries[i];

        const ret = readData1Entry(masterData, element.id, idSeeds[element.id] ? idSeeds[element.id] : undefined);

        var fileName = libNames[element.id] ?? "";

        if(fileName == ""){
            fileName = `${INPUT_LIB_NAME}_type${element.id}.so`;
        }

        FS.writeFile(ret, path.join(OUTPUT_PATH, fileName) );
    }

    var masterLibName = INPUT_LIB_NAME + "_decoded.dat";

    FS.writeFile(MASTER_ELF_DATA, path.join(OUTPUT_PATH, masterLibName));
} if(ARGV.legacy){
    runLegacy();
} else {
    if(LOUSEROffset == 0){
        console.log("[!] Error: Couldn't find LOUSER section of data.");

        process.exit(0);
    }

    const LOUSER_DATA = MASTER_ELF_DATA.subarray(LOUSEROffset, LOUSEROffset + LOUSER_SIZE);

    const LOUSER_START = ARGV.LOUSER_START;

    const tableData = LOUSER_DATA.subarray(LOUSER_START, LOUSER_START + 32);

    var LOUSER_SIZE_LEFT = LOUSER_SIZE - ARGV.LOUSER_START;
    // 32 bytes
    const masterTable = DecodeMasterTable(tableData);

    console.log("[*] masterTable", masterTable);

    const MASTER_SIZE = pageAlign(masterTable.offset + masterTable.elfSize, 4, 1);

    var SHT_LOUSER_AFTER_MASTER_START = LOUSER_START + MASTER_SIZE;

    LOUSER_SIZE_LEFT -= MASTER_SIZE;

    const ELFMaster0 = LOUSER_DATA.subarray(
        LOUSER_START + masterTable.offset, 
        SHT_LOUSER_AFTER_MASTER_START
    )

    PRNG_MASTER(masterTable.seed, ELFMaster0, masterTable.elfSize, 0);

    var masterLibName = `libLv0.so`;

    FS.writeFile(ELFMaster0, path.join(OUTPUT_PATH, masterLibName));

    console.log(`[+] Created ${masterLibName}`);

    var SHT_LOUSER_AFTER_MASTER = LOUSER_DATA.subarray(SHT_LOUSER_AFTER_MASTER_START, LOUSER_DATA.byteLength);

    const SHT_LOUSER_SEED = decodeSeedMaster(SHT_LOUSER_AFTER_MASTER, 226);
    
    var ELF243AddressPlus8 = SHT_LOUSER_AFTER_MASTER.subarray(8, LOUSER_DATA.byteLength);

    LOUSER_SIZE_LEFT -= 8;

    var Lv0Seed = 0x745F;

    if(ARGV.seed0 != undefined){
        Lv0Seed = ELFMaster0.readUint32LE(ARGV.seed0);
    }

    if(ARGV.aes_table0 == undefined){
        console.log(`[!] Stopping: Need aes_table0 and seed0 offsets to continue.`);

        process.exit(0);
    }

    const AES_TABLE0 = ELFMaster0.subarray(ARGV.aes_table0, ELFMaster0.length);

    /**
     * @type {Buffer|undefined}
     */
    var Lv1Buffer;

    /**
     * @type {number|undefined}
     */
    var Lv1Type;

    /**
     * @type {Buffer|undefined}
     */
    var AES_TABLE1;

    var Lv1Seed = 0x5378;

    /**
     * @type {Buffer|undefined}
     */
    var Lv2Buffer;

    /**
     * @type {number|undefined}
     */
    var Lv2Type;
    
    /**
     * @type {Buffer|undefined}
     */
    var AES_TABLE2;

    var Lv2Seed = 0x5B33;

    /**
     * @type {Buffer|undefined}
     */
    var Lv3Buffer;

    /**
     * @type {number|undefined}
     */
    var Lv3Type;
    
    /**
     * @type {Buffer|undefined}
     */
    var AES_TABLE3;

    var Lv3Seed = 0x2699;

    /**
     * @type {Buffer|undefined}
     */
    var Lv4Buffer;

    /**
     * @type {number|undefined}
     */
    var Lv4Type;
    
    /**
     * @type {Buffer|undefined}
     */
    var AES_TABLE4;

    var Lv4Seed = 0x6892;

    /**
     * @type {Buffer|undefined}
     */
    var Lv5Buffer;

    /**
     * @type {number|undefined}
     */
    var Lv5Type;
    
    /**
     * @type {Buffer|undefined}
     */
    var AES_TABLE5;

    var Lv5Seed = 0x7FBA;

    /**
     * @type {Buffer|undefined}
     */
    var Lv6Buffer;

    /**
     * @type {number|undefined}
     */
    var Lv6Type;
    
    /**
     * @type {Buffer|undefined}
     */
    var AES_TABLE6;

    var Lv6Seed = 0x161F;

    var Lv6TableSeed = 0x56BB96B0;

    /**
     * @type {Buffer|undefined}
     */
    var offsetsBuffer6;

    /**
     * @type {Buffer|undefined}
     */
    var Lv7Buffer;

    /**
     * @type {number|undefined}
     */
    var Lv7Type;
    
    /**
     * @type {Buffer|undefined}
     */
    var AES_TABLE7;

    var Lv7Seed = 0x6E2F;

    // need loop here, by my count there is 4
    var loopCount = 1;

    var offsetTracker = LOUSEROffset + SHT_LOUSER_AFTER_MASTER_START;

    var offsetTrackerNext;

    // Lv0
    for (let i = 0; i < loopCount; i++) {
        const subTable = decodeSubTableMaster(ELF243AddressPlus8, i, SHT_LOUSER_SEED);

        LOUSER_SIZE_LEFT -= 92;

        if(i == 0){
            loopCount = (subTable.SliceTableOffset - 8) / 92;

            if(loopCount > 0xFF){
                console.log(`[!] Error: Amount of subTables too large. May have decoded incorrectly. ${loopCount} > 255`);

                process.exit(0);
            }

            console.log("[+] Lv0subTables:", loopCount, `Start:`, FS.makeOffset(offsetTracker), "Size:", (loopCount * 92) + 8);
        }

        console.log(`[*] Lv0subTable${i}`, subTable);

        console.log(`[!] type${subTable.elfType} Slice:`, FS.makeOffset(offsetTracker + subTable.SliceTableOffset));

        const SHT_LOUSER_AFTER_MASTER_START_PlusSliceTableOffset = LOUSER_DATA.subarray(
            SHT_LOUSER_AFTER_MASTER_START + subTable.SliceTableOffset
        );

        if(subTable.skipProcess){
            Lv1Buffer = LOUSER_DATA.subarray(
                SHT_LOUSER_AFTER_MASTER_START + subTable.SliceTableOffset
            )

            offsetTrackerNext = offsetTracker + subTable.SliceTableOffset;

            var fileName = subTable.name;

            if(subTable.name == ""){
                fileName = `${INPUT_LIB_NAME}_Lv0_type${subTable.elfType}.bin`;
            }

            FS.writeFile(Lv1Buffer, path.join(OUTPUT_PATH, fileName));

            console.log(`[+] Created ${fileName}`);
        } else {
            const ELFBuffer = decodeNextLvMaster(SHT_LOUSER_AFTER_MASTER_START_PlusSliceTableOffset, AES_TABLE0, Lv0Seed);

            var fileName = subTable.name;

            if(subTable.name == ""){
                fileName = `${INPUT_LIB_NAME}_Lv0_type${subTable.elfType}.so`;
            }

            if(subTable.ELFHeadersOffset != 0){
                const SHT_LOUSER_AFTER_MASTER_START_PlusELFChunk2Offset = LOUSER_DATA.subarray(
                    SHT_LOUSER_AFTER_MASTER_START + subTable.ELFHeadersOffset
                );

                console.log(`[!] type${subTable.elfType} Headers:`, FS.makeOffset(offsetTracker + subTable.ELFHeadersOffset));
                
                decodeNextLvMaster(SHT_LOUSER_AFTER_MASTER_START_PlusELFChunk2Offset, AES_TABLE0, Lv0Seed, ELFBuffer);
            }

            if(i == (loopCount - 1)){
                Lv1Type = subTable.elfType;

                if(ARGV.seed1 != undefined){
                    Lv1Seed = ELFBuffer.readUint32LE(ARGV.seed1);
                }

                if(ARGV.aes_table1 != undefined){
                    AES_TABLE1 = ELFBuffer.subarray(ARGV.aes_table1, ELFBuffer.length);
                }
            }
            
            FS.writeFile(ELFBuffer, path.join(OUTPUT_PATH, fileName));

            console.log(`[+] Created ${fileName}`);
        }
    }

    offsetTracker = offsetTrackerNext;

    if( ARGV.seed1 == undefined || 
        ARGV.aes_table1 == undefined
    ){
        console.log(`[!] Stopping: Need aes_table1 and seed1 offsets from within the libLv1.so to continue.`);

        process.exit(0);
    }

    // Lv1
    if( Lv1Buffer == undefined || 
        Lv1Type == undefined || 
        AES_TABLE1 == undefined){
        console.log(`[!] Error: Lv0 finished without finding next level.`);

        process.exit(0);
    } else {
        const TYPE_243_SEED = decodeSeedSub(Lv1Buffer, Lv1Type);

        var sizeLeft = Lv1Buffer.length;

        var offset = 0;

        var ELF243AddressPlus8 = Lv1Buffer.subarray(8, Lv1Buffer.byteLength);

        offset += 8;

        sizeLeft -= 8;

        var loopCount = 1;

        for (let i = 0; i < loopCount; i++) {
            const subTable = decodeSubTableSub(ELF243AddressPlus8, i, TYPE_243_SEED, offset);

            ELF243AddressPlus8 = ELF243AddressPlus8.subarray(92, ELF243AddressPlus8.length);

            offset += 92;

            sizeLeft -= 92;

            if(i == 0){
                loopCount = (subTable.SliceTableOffset - 8) / 92;

                if(loopCount > 0xFF){
                    console.log(`[!] Error: Amount of subTables too large. May have decoded incorrectly. ${loopCount} > 255`);

                    process.exit(0);
                }

                console.log("[+] Lv1subTables:", loopCount, `Start:`, FS.makeOffset(offsetTracker), "Size:", (loopCount * 92) + 8);
            }

            console.log(`[*] Lv1subTable${i}`, subTable);

            console.log(`[!] type${subTable.elfType} Slice:`, FS.makeOffset(offsetTracker + subTable.SliceTableOffset));

            const buffer243_PlusSliceTableOffset = Lv1Buffer.subarray(
                subTable.SliceTableOffset
            );

            if(subTable.skipProcess){
                Lv2Buffer = Lv1Buffer.subarray(
                    subTable.SliceTableOffset
                )

                offsetTrackerNext = offsetTracker + subTable.SliceTableOffset;
                
                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv1_type${subTable.elfType}.bin`;
                }

                FS.writeFile(Lv2Buffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            } else {
                const ELFBuffer = decodeNextLvSub(buffer243_PlusSliceTableOffset, AES_TABLE1, Lv1Seed);

                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv1_type${subTable.elfType}.so`;
                }

                if(subTable.ELFHeadersOffset != 0){
                    const buffer243_PlusELFChunk2Offset = Lv1Buffer.subarray(
                        subTable.ELFHeadersOffset
                    );

                    console.log(`[!] type${subTable.elfType} Headers:`, FS.makeOffset(offsetTracker + subTable.ELFHeadersOffset));
                    
                    decodeNextLvSub(buffer243_PlusELFChunk2Offset, AES_TABLE1, Lv1Seed, ELFBuffer);
                }

                if(i == (loopCount - 1)){
                    Lv2Type = subTable.elfType;

                    if(ARGV.seed2 != undefined){
                        Lv2Seed = ELFBuffer.readUint32LE(ARGV.seed2);
                    }

                    if(ARGV.aes_table2 != undefined){
                        AES_TABLE2 = ELFBuffer.subarray(ARGV.aes_table2, ELFBuffer.length);
                    }
                }
                
                FS.writeFile(ELFBuffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            }
        }
    }

    offsetTracker = offsetTrackerNext;

    loopCount = 1;

    if( ARGV.seed2 == undefined || 
        ARGV.aes_table2 == undefined
    ){
        console.log(`[!] Stopping: Need aes_table2 and seed2 offsets from within the libLv2.so to continue.`);

        process.exit(0);
    }

    // Lv2
    if( Lv2Buffer == undefined || 
        Lv2Type == undefined || 
        AES_TABLE2 == undefined){
        console.log(`[!] Error: Lv1 finished without finding next level.`);

        process.exit(0);
    } else {
        const TYPE_244_SEED = decodeSeedSub(Lv2Buffer, Lv2Type);

        var sizeLeft = Lv2Buffer.length;

        var offset = 0;

        var ELF244AddressPlus8 = Lv2Buffer.subarray(8, Lv2Buffer.byteLength);

        offset += 8;

        sizeLeft -= 8;

        var loopCount = 1;

        for (let i = 0; i < loopCount; i++) {
            const subTable = decodeSubTableSub(ELF244AddressPlus8, i, TYPE_244_SEED, offset);

            ELF244AddressPlus8 = ELF244AddressPlus8.subarray(92, ELF244AddressPlus8.length);

            offset += 92;

            sizeLeft -= 92;

            if(i == 0){
                loopCount = (subTable.SliceTableOffset - 8) / 92;

                if(loopCount > 0xFF){
                    console.log(`[!] Error: Amount of subTables too large. May have decoded incorrectly. ${loopCount} > 255`);

                    process.exit(0);
                }

                console.log("[+] Lv2subTables:", loopCount, `Start:`, FS.makeOffset(offsetTracker), "Size:", (loopCount * 92) + 8);
            }

            console.log(`[*] Lv2subTable${i}`, subTable);

            console.log(`[!] type${subTable.elfType} Slice:`, FS.makeOffset(offsetTracker + subTable.SliceTableOffset));

            const buffer244_PlusSliceTableOffset = Lv2Buffer.subarray(
                subTable.SliceTableOffset
            );

            if(subTable.skipProcess){
                Lv3Buffer = Lv2Buffer.subarray(
                    subTable.SliceTableOffset
                )

                offsetTrackerNext = offsetTracker + subTable.SliceTableOffset;
                
                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv2_type${subTable.elfType}.bin`;
                }

                FS.writeFile(Lv3Buffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            } else if(subTable.SliceTableSize != 0) {
                const ELFBuffer = decodeNextLvSub(buffer244_PlusSliceTableOffset, AES_TABLE2, Lv2Seed);

                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv2_type${subTable.elfType}.so`;
                }

                if(subTable.ELFHeadersOffset != 0){
                    const buffer244_PlusELFChunk2Offset = Lv2Buffer.subarray(
                        subTable.ELFHeadersOffset
                    );

                    console.log(`[!] type${subTable.elfType} Headers:`, FS.makeOffset(offsetTracker + subTable.ELFHeadersOffset));

                    decodeNextLvSub(buffer244_PlusELFChunk2Offset, AES_TABLE2, Lv2Seed, ELFBuffer);
                }

                if(i == (loopCount - 1)){
                    Lv3Type = subTable.elfType;

                    if(ARGV.seed3 != undefined){
                        Lv3Seed = ELFBuffer.readUint32LE(ARGV.seed3);
                    }

                    if(ARGV.aes_table3 != undefined){
                        AES_TABLE3 = ELFBuffer.subarray(ARGV.aes_table3, ELFBuffer.length);
                    }
                }
                
                FS.writeFile(ELFBuffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            }
        }
    }

    offsetTracker = offsetTrackerNext;

    if( ARGV.seed3 == undefined || 
        ARGV.aes_table3 == undefined
    ){
        console.log(`[!] Stopping: Need aes_table3 and seed3 offsets from within the libLv3.so to continue.`);

        process.exit(0);
    }

    // Lv3
    if( Lv3Buffer == undefined || 
        Lv3Type == undefined || 
        AES_TABLE3 == undefined){
        console.log(`[!] Error: Lv2 finished without finding next level.`);

        process.exit(0);
    } else {
        const TYPE_245_SEED = decodeSeedSub(Lv3Buffer, Lv3Type);

        var sizeLeft = Lv3Buffer.length;

        var offset = 0;

        var ELF245AddressPlus8 = Lv3Buffer.subarray(8, Lv3Buffer.byteLength);

        offset += 8;

        sizeLeft -= 8;

        var loopCount = 1;

        for (let i = 0; i < loopCount; i++) {
            const subTable = decodeSubTableSub(ELF245AddressPlus8, i, TYPE_245_SEED, offset);

            ELF245AddressPlus8 = ELF245AddressPlus8.subarray(92, ELF245AddressPlus8.length);

            offset += 92;

            sizeLeft -= 92;

            if(i == 0){
                loopCount = (subTable.SliceTableOffset - 8) / 92;

                if(loopCount > 0xFF){
                    console.log(`[!] Error: Amount of subTables too large. May have decoded incorrectly. ${loopCount} > 255`);

                    process.exit(0);
                }

                console.log("[+] Lv3subTables:", loopCount,`Start:`, FS.makeOffset(offsetTracker), "Size:", (loopCount * 92) + 8);
            }

            console.log(`[*] Lv3subTable${i}`, subTable);

            console.log(`[!] type${subTable.elfType} Slice:`, FS.makeOffset(offsetTracker + subTable.SliceTableOffset));

            const buffer245_PlusSliceTableOffset = Lv3Buffer.subarray(
                subTable.SliceTableOffset
            );

            if(subTable.skipProcess){
                Lv4Buffer = Lv3Buffer.subarray(
                    subTable.SliceTableOffset
                )

                offsetTrackerNext = offsetTracker + subTable.SliceTableOffset;
                
                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv3_type${subTable.elfType}.bin`;
                }

                FS.writeFile(Lv4Buffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            } else if(subTable.SliceTableSize != 0) {
                const ELFBuffer = decodeNextLvSub(buffer245_PlusSliceTableOffset, AES_TABLE3, Lv3Seed);

                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv3_type${subTable.elfType}.so`;
                }

                if(subTable.ELFHeadersOffset != 0){
                    const buffer245_PlusELFChunk2Offset = Lv3Buffer.subarray(
                        subTable.ELFHeadersOffset
                    );

                    console.log(`[!] type${subTable.elfType} Headers:`, FS.makeOffset(offsetTracker + subTable.ELFHeadersOffset));

                    decodeNextLvSub(buffer245_PlusELFChunk2Offset, AES_TABLE3, Lv3Seed, ELFBuffer);
                }

                if(i == (loopCount - 1)){
                    Lv4Type = subTable.elfType;

                    if(ARGV.seed4 != undefined){
                        Lv4Seed = ELFBuffer.readUint32LE(ARGV.seed4);
                    }

                    if(ARGV.aes_table4 != undefined){
                        AES_TABLE4 = ELFBuffer.subarray(ARGV.aes_table4, ELFBuffer.length);
                    }
                }
                
                FS.writeFile(ELFBuffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            }
        }
    }

    offsetTracker = offsetTrackerNext;

    if( ARGV.seed4 == undefined || 
        ARGV.aes_table4 == undefined
    ){
        console.log(`[!] Stopping: Need aes_table4 and seed4 offsets from within the libLv4.so to continue.`);

        process.exit(0);
    }

    // Lv4
    if( Lv4Buffer == undefined || 
        Lv4Type == undefined || 
        AES_TABLE4 == undefined){
        console.log(`[!] Error: Lv3 finished without finding next level.`);

        process.exit(0);
    } else {
        const TYPE_246_SEED = decodeSeedSub(Lv4Buffer, Lv4Type);

        var sizeLeft = Lv4Buffer.length;

        var offset = 0;

        var ELF246AddressPlus8 = Lv4Buffer.subarray(8, Lv4Buffer.byteLength);

        offset += 8;

        sizeLeft -= 8;

        var loopCount = 1;

        for (let i = 0; i < loopCount; i++) {
            const subTable = decodeSubTableSub(ELF246AddressPlus8, i, TYPE_246_SEED, offset);

            ELF246AddressPlus8 = ELF246AddressPlus8.subarray(92, ELF246AddressPlus8.length);

            offset += 92;

            sizeLeft -= 92;

            if(i == 0){
                loopCount = (subTable.SliceTableOffset - 8) / 92;

                if(loopCount > 0xFF){
                    console.log(`[!] Error: Amount of subTables too large. May have decoded incorrectly. ${loopCount} > 255`);

                    process.exit(0);
                }

                console.log("[+] Lv4subTables:", loopCount,`Start:`, FS.makeOffset(offsetTracker), "Size:", (loopCount * 92) + 8);
            }

            console.log(`[*] Lv4subTable${i}`, subTable);

            console.log(`[!] type${subTable.elfType} Slice:`, FS.makeOffset(offsetTracker + subTable.SliceTableOffset));

            const buffer246_PlusSliceTableOffset = Lv4Buffer.subarray(
                subTable.SliceTableOffset
            );

            if(subTable.skipProcess){
                Lv5Buffer = Lv4Buffer.subarray(
                    subTable.SliceTableOffset
                )

                offsetTrackerNext = offsetTracker + subTable.SliceTableOffset;
                
                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv4_type${subTable.elfType}.bin`;
                }

                FS.writeFile(Lv5Buffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            } else if(subTable.SliceTableSize != 0) {
                const ELFBuffer = decodeNextLvSub(buffer246_PlusSliceTableOffset, AES_TABLE4, Lv4Seed);

                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv4_type${subTable.elfType}.so`;
                }

                if(subTable.ELFHeadersOffset != 0){
                    const buffer246_PlusELFChunk2Offset = Lv4Buffer.subarray(
                        subTable.ELFHeadersOffset
                    );

                    console.log(`[!] type${subTable.elfType} Headers:`, FS.makeOffset(offsetTracker + subTable.ELFHeadersOffset));

                    decodeNextLvSub(buffer246_PlusELFChunk2Offset, AES_TABLE4, Lv4Seed, ELFBuffer);
                }

                if(i == (loopCount - 1)){
                    Lv5Type = subTable.elfType;

                    if(ARGV.seed5 != undefined){
                        Lv5Seed = ELFBuffer.readUint32LE(ARGV.seed5);
                    }

                    if(ARGV.aes_table5 != undefined){
                        AES_TABLE5 = ELFBuffer.subarray(ARGV.aes_table5, ELFBuffer.length);
                    }
                }
                
                FS.writeFile(ELFBuffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            }
        }
    }

    offsetTracker = offsetTrackerNext;

    var data185;

    var data158;

    var data194;

    var data195;

    if( ARGV.seed5 == undefined || 
        ARGV.aes_table5 == undefined
    ){
        console.log(`[!] Stopping: Need aes_table5 and seed5 offsets from within the libLv5.so to continue.`);

        process.exit(0);
    }

    var offsetTrackerLast;

    // Lv5 & Lv6
    if( Lv5Buffer == undefined || 
        Lv5Type == undefined || 
        AES_TABLE5 == undefined){
        console.log(`[!] Error: Lv4 finished without finding next level.`);

        process.exit(0);
    } else {
        const TYPE_247_SEED = decodeSeedSub(Lv5Buffer, Lv5Type);

        var sizeLeft = Lv5Buffer.length;

        var offset = 0;

        var ELF247AddressPlus8 = Lv5Buffer.subarray(8, Lv5Buffer.byteLength);

        offset += 8;

        sizeLeft -= 8;

        var loopCount = 1;

        for (let i = 0; i < loopCount; i++) {
            const subTable = decodeSubTableSub(ELF247AddressPlus8, i, TYPE_247_SEED, offset);

            ELF247AddressPlus8 = ELF247AddressPlus8.subarray(92, ELF247AddressPlus8.length);

            offset += 92;

            sizeLeft -= 92;

            if(i == 0){
                loopCount = (subTable.SliceTableOffset - 8) / 92;

                if(loopCount > 0xFF){
                    console.log(`[!] Error: Amount of subTables too large. May have decoded incorrectly. ${loopCount} > 255`);

                    process.exit(0);
                }

                console.log("[+] Lv5subTables:", loopCount,`Start:`, FS.makeOffset(offsetTracker), "Size:", (loopCount * 92) + 8);
            }

            console.log(`[*] Lv5subTable${i}`, subTable);

            console.log(`[!] type${subTable.elfType} Slice:`, FS.makeOffset(offsetTracker + subTable.SliceTableOffset));

            const buffer247_PlusSliceTableOffset = Lv5Buffer.subarray(
                subTable.SliceTableOffset
            );

            if(subTable.skipProcess){
                var nextBuffer = Lv5Buffer.subarray(
                    subTable.SliceTableOffset
                )
                
                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv5_type${subTable.elfType}.bin`;
                }

                FS.writeFile(nextBuffer, path.join(OUTPUT_PATH, fileName));

                if(subTable.elfType == 157){
                    Lv6Buffer = nextBuffer;

                    offsetTrackerNext = offsetTracker + subTable.SliceTableOffset;
                }

                if(subTable.elfType == 248){
                    Lv7Buffer = nextBuffer;

                    offsetTrackerLast = offsetTracker + subTable.SliceTableOffset;
                }

                console.log(`[+] Created ${fileName}`);
            } else if(subTable.SliceTableSize != 0) {
                const ELFBuffer = decodeNextLvSub(buffer247_PlusSliceTableOffset, AES_TABLE5, Lv5Seed);

                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv5_type${subTable.elfType}.so`;
                }

                if(subTable.ELFHeadersOffset != 0){
                    const buffer247_PlusELFChunk2Offset = Lv5Buffer.subarray(
                        subTable.ELFHeadersOffset
                    );

                    console.log(`[!] type${subTable.elfType} Headers:`, FS.makeOffset(offsetTracker + subTable.ELFHeadersOffset));

                    decodeNextLvSub(buffer247_PlusELFChunk2Offset, AES_TABLE5, Lv5Seed, ELFBuffer);
                }

                if(subTable.elfType == 155){
                    Lv6Type = subTable.elfType;

                    if(ARGV.seed6 != undefined){
                        Lv6Seed = ELFBuffer.readUint32LE(ARGV.seed6);
                    }

                    if(ARGV.aes_table6 != undefined){
                        AES_TABLE6 = ELFBuffer.subarray(ARGV.aes_table6, ELFBuffer.length);
                    }

                    if(ARGV.seed_table6){
                        Lv6TableSeed = ELFBuffer.readUint32LE(ARGV.seed_table6);
                    }

                    if(ARGV.offsets6){
                        const count = ELFBuffer.readUint32LE(ARGV.offsets6);

                        offsetsBuffer6 = ELFBuffer.subarray(ARGV.offsets6,ARGV.offsets6 + ((count - 1) * 8) + 4);
                    }
                }

                if(subTable.elfType == 232){
                    Lv7Type = subTable.elfType;

                    if(ARGV.seed7 != undefined){
                        Lv7Seed = ELFBuffer.readUint32LE(ARGV.seed7);
                    }

                    if(ARGV.aes_table7 != undefined){
                        AES_TABLE7 = ELFBuffer.subarray(ARGV.aes_table7, ELFBuffer.length);
                    }
                }
                
                FS.writeFile(ELFBuffer, path.join(OUTPUT_PATH, fileName));

                if(subTable.elfType == 158){
                    data158 = ELFBuffer;
                }

                if(subTable.elfType == 185){
                    data185 = ELFBuffer;
                }

                if(subTable.elfType == 194 && ELFBuffer.length != 0){
                    data194 = ELFBuffer;
                }

                if(subTable.elfType == 195 && ELFBuffer.length != 0){
                    data195 = ELFBuffer;
                }

                console.log(`[+] Created ${fileName}`);
            }
        }
    }

    offsetTracker = offsetTrackerNext;

    if( ARGV.seed6 == undefined || 
        ARGV.aes_table6 == undefined ||
        Lv6Buffer == undefined || 
        Lv6Type == undefined || 
        Lv6TableSeed == undefined ||
        AES_TABLE6 == undefined ||
        data158 == undefined
    ){
        console.log(`[!] Warning: Need aes_table6 and seed6 offsets from within the libLv6.so to recreate master lib.`);
    } else {
        console.log(`[*] Writing master lib strings and symbols.`);
        // copy dynsym dynstr
        isARM32 ? 
            parseData158_32(data158, MASTER_ELF_DATA, SHT_DYNAMICOffset, SHT_STRTAB) :
            parseData158_64(data158, MASTER_ELF_DATA, SHT_DYNAMICOffset, SHT_STRTAB);

        const data157meta = decodeSubTable157(Lv6Buffer, Lv6TableSeed);

        console.log(`[*] Lv6subTable0`, data157meta);

        const SliceTableOffset = Lv6Buffer.subarray(data157meta.SliceTableOffset, Lv6Buffer.length);

        console.log(`[*] Writing master lib programming layer.`);

        console.log(`[!] type${data157meta.elfType} Slice:`, FS.makeOffset(offsetTracker + data157meta.SliceTableOffset));
        // adds programming
        MASTER_ELF_DATA = decodeNextLvSub(SliceTableOffset, AES_TABLE6, Lv6Seed, MASTER_ELF_DATA);
        // parse 195 and use offsets to spit 194 data
        if(isARM32 && data194 && data195 && ARGV.offsets6 && offsetsBuffer6){
            console.log(`[*] Matching function offsets.`);

            const meta195 = parse195(data195);

            const count = offsetsBuffer6.readUInt32LE(0);

            const type194Splits = [];

            for (let z = 0; z < (count-1); z++) {
                const entry = (z * 8) + 4;

                const start = offsetsBuffer6.readUint32LE(entry);

                const size = offsetsBuffer6.readUint32LE(entry + 4);

                type194Splits.push({
                    start: offsetsBuffer6.readUint32LE(entry),

                    size: offsetsBuffer6.readUint32LE(entry + 4),

                    buffer: data194.subarray(start, start+ size),
                })
            }

            var masterCount = 0;

            for (let z = 0; z < meta195.length; z++) {
                var el = meta195[z];

                const masterOff = el.offset;

                var read = 0;

                var loop = 0;

                if(el.dst == -1){ // master
                    var off = MASTER_ELF_DATA.readUint32LE(el.offset);
                    do {
                        var buf = type194Splits[el.src].buffer;
                        //console.log(`[${loop}] ${el.dst} -> ${FS.makeOffset(el.offset)} = ${el.src} -> ${FS.makeOffset(off)}`);
                        if(off > buf.length){
                            console.log(`[!] offset ${el.offset} lost.`);

                            break;
                        }

                        do {
                            read = buf.readUint32LE(off); off += 4;
                        } while (read != 3844075524);

                        if(off > buf.length){
                            console.log(`[!] offset ${el.offset} lost.`);

                            break;
                        }

                        read = buf.readUint32LE(off);

                        if(read > data194.length){
                            break;
                        }
                        //console.log(`[${loop}] ${el.dst} -> ${FS.makeOffset(el.offset)} = ${el.src} -> ${FS.makeOffset(off)}`);
                        loop++;
                        // @ts-ignore
                        el = meta195.find((item)=> item.offset == off && item.dst == el.src);

                        off = read;
                    } while (el.src != -1);

                    console.log(`[${masterCount}] function match (${loop}) ${FS.makeOffset(masterOff)} -> ${FS.makeOffset(read)}`);

                    masterCount++;

                    MASTER_ELF_DATA.writeUint32LE(read, masterOff);
                }
            }
        }

        const dataHeadersOffset = Lv6Buffer.subarray(data157meta.ELFHeadersOffset, Lv6Buffer.length);

        console.log(`[*] Creating IDA rename script.`);

        console.log(`[!] type${data157meta.elfType} Headers:`, FS.makeOffset(offsetTracker + data157meta.ELFHeadersOffset));

        const dataHeaders = decodeNextLvSub(dataHeadersOffset, AES_TABLE6, Lv6Seed);

        FS.writeFile(dataHeaders, path.join(OUTPUT_PATH, `${INPUT_LIB_NAME}_Lv5_type157_headers.dat`));
        // Convert 157 headers into python script for renaming
        const { REL, JMPREL } = isARM32 ? parse157Headers32(dataHeaders) : parse157Headers64(dataHeaders);
        // 185 copies offset to direct c functions (memset, strcpy etc) pulled from Lv6
        // add them to jmp
        if(data185){
            parse185(data185, JMPREL);
        }
        const {diff, min }= isARM32 ? 
            fixData32_SIZE(MASTER_ELF_DATA) : 
            fixData64_SIZE(MASTER_ELF_DATA);

        const pyStript =  makePythonReplacementScript(REL, JMPREL, min, diff);
        
        FS.writeFile(pyStript, path.join(OUTPUT_PATH, `ida_renamer_${INPUT_LIB_NAME}.py`));
        

        FS.writeFile(MASTER_ELF_DATA, path.join(OUTPUT_PATH, INPUT_LIB_NAME + "_decrypted.so"));

        console.log(`[+] Created ${INPUT_LIB_NAME + "_decrypted.so"}`);
    }  
    
    offsetTracker = offsetTrackerLast;

    if( ARGV.seed7 == undefined || 
        ARGV.aes_table7 == undefined
    ){
        console.log(`[!] Stopping: Need aes_table7 and seed7 offsets from within the libLv7.so to continue.`);

        process.exit(0);
    }

    // Lv7
    if( Lv7Buffer == undefined || 
        Lv7Type == undefined || 
        AES_TABLE7 == undefined){
        console.log(`[!] Error: Lv5 finished without finding next level.`);

        process.exit(0);
    } else {
        const TYPE_248_SEED = decodeSeedSub(Lv7Buffer, Lv7Type);

        var sizeLeft = Lv7Buffer.length;

        var offset = 0;

        var ELF248AddressPlus8 = Lv7Buffer.subarray(8, Lv7Buffer.byteLength);

        offset += 8;

        sizeLeft -= 8;

        var loopCount = 1;

        for (let i = 0; i < loopCount; i++) {
            const subTable = decodeSubTableSub(ELF248AddressPlus8, i, TYPE_248_SEED, offset);

            ELF248AddressPlus8 = ELF248AddressPlus8.subarray(92, ELF248AddressPlus8.length);

            offset += 92;

            sizeLeft -= 92;

            if(i == 0){
                loopCount = (subTable.SliceTableOffset - 8) / 92;

                if(loopCount > 0xFF){
                    console.log(`[!] Error: Amount of subTables too large. May have decoded incorrectly. ${loopCount} > 255`);

                    process.exit(0);
                }

                console.log("[+] Lv7subTables:", loopCount,`Start:`, FS.makeOffset(offsetTracker), "Size:", (loopCount * 92) + 8);
            }

            console.log(`[*] Lv7subTable${i}`, subTable);

            console.log(`[!] type${subTable.elfType} Slice:`, FS.makeOffset(offsetTracker + subTable.SliceTableOffset));

            const buffer248_PlusSliceTableOffset = Lv7Buffer.subarray(
                subTable.SliceTableOffset
            );

            if(subTable.skipProcess){
                var finalbuffer = Lv7Buffer.subarray(
                    subTable.SliceTableOffset
                )
                
                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv7_type${subTable.elfType}.bin`;
                }

                FS.writeFile(finalbuffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            } else if(subTable.SliceTableSize != 0) {
                const ELFBuffer = decodeNextLvSub(buffer248_PlusSliceTableOffset, AES_TABLE7, Lv7Seed);

                var fileName = subTable.name;

                if(subTable.name == ""){
                    fileName = `${INPUT_LIB_NAME}_Lv7_type${subTable.elfType}.so`;
                }

                if(subTable.ELFHeadersOffset != 0){
                    const buffer248_PlusELFChunk2Offset = Lv7Buffer.subarray(
                        subTable.ELFHeadersOffset
                    );

                    console.log(`[!] type${subTable.elfType} Headers:`, FS.makeOffset(offsetTracker + subTable.ELFHeadersOffset));

                    decodeNextLvSub(buffer248_PlusELFChunk2Offset, AES_TABLE7, Lv7Seed, ELFBuffer);
                }
                
                FS.writeFile(ELFBuffer, path.join(OUTPUT_PATH, fileName));

                console.log(`[+] Created ${fileName}`);
            }
        }
    }
}