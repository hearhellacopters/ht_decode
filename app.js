// @ts-check

// node app.js --file ./libs/lib__57d5__.so --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C

const pack = require('./package.json');
const path = require("path");
const { FS } = require("./src/File");
const { 
    Command, 
    Option 
} = require('commander');
const { 
    readLvInfo,
    TABLE_ENTRY_SIZE,
    readTableEntry,
    decodeELF,
    praseELF32,
    read241
} = require("./src/Structures");

/**
 * How the app parses arguments passed to it at the command line level.
 * 
 * @class
 */
const PROGRAM = new Command();

const hasFile = new Option('-f, --file <string>', 'Location of the lib file');

hasFile.required = true; hasFile.mandatory = true;

const hasOutput = new Option('-o, --output <string>', 'Location of for the decompiled lib files (defaults to input folder)');

const hasLv0 = new Option('-0, --Lv0 <string>', 'The location of the Lv0 structure within the file. (can be in hex or decimal)');

hasLv0.required = true; hasLv0.mandatory = true;

const hasLv1 = new Option('-1, --Lv1 <string>', 'The location of the Lv1 structure within the last lib created. (can be in hex or decimal)');

const hasLv2 = new Option('-2, --Lv2 <string>', 'The location of the Lv2 structure within the last lib created. (can be in hex or decimal)');

const hasLv3 = new Option('-3, --Lv3 <string>', 'The location of the Lv3 structure within the last lib created. (can be in hex or decimal)');

const hasLv4 = new Option('-4, --Lv4 <string>', 'The location of the Lv4 structure within the last lib created. (can be in hex or decimal)');

// Set commands to program for
PROGRAM
    .name('ht_decoder')
    .description(`\x1b[36mFor decompiling Android libs\x1b[0m`)
    .version(pack.version)
    .addOption(hasFile)
    .addOption(hasOutput)
    .addOption(hasLv0)
    .addOption(hasLv1)
    .addOption(hasLv2)
    .addOption(hasLv3)
    .addOption(hasLv4)

PROGRAM.parse(process.argv);

/**
 * Command line arguments.
 */
const ARGV = PROGRAM.opts();

/**
 * Converts string to number
 * 
 * @param {string} str 
 */
function _parseNumber(str) {
    if (str[0] == "0" && str[1] == "x") { // hex
        return parseInt(str, 16);
    }

    return parseInt(str, 10);
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

const DIR_NAME = _init_dir_name();

var INPUT_LIB_PATH = "";

var INPUT_LIB_NAME = "";

// get file path
try {
    if (!FS.fileExists(ARGV.file)) {
        if (path.isAbsolute(ARGV.file)) {
            console.log(`error: Can't find file ${ARGV.file}`);

            process.exit(0);
        }

        const homePath = path.join(DIR_NAME, ARGV.file);

        if (!FS.fileExists(homePath)) {
            console.log(`error: Can't find file ${homePath}`);

            process.exit(0);
        }

        INPUT_LIB_PATH = homePath;
    } else {
        INPUT_LIB_PATH = ARGV.file;

        INPUT_LIB_NAME = path.parse(INPUT_LIB_PATH).name;
    }
} catch (error) {
    // @ts-ignore
    throw new Error(error);
} 

console.log("Processing: ",INPUT_LIB_NAME);

var OUTPUT_PATH = "";

try {
    if(ARGV.output == undefined){
        OUTPUT_PATH = path.dirname(INPUT_LIB_PATH);
    } else {
        if (!FS.directoryExists(ARGV.output)) {
            if (path.isAbsolute(ARGV.output)) {
                console.log(`error: Can't find file ${ARGV.output}`);

                process.exit(0);
            }

            const homePath = path.join(DIR_NAME, ARGV.output);

            if (!FS.directoryExists(homePath)) {
                console.log("Created output folder: " + homePath);

                FS.createDirectory(homePath);
            }

            OUTPUT_PATH = homePath;
        } else {
            FS.createDirectory(ARGV.output);

            OUTPUT_PATH = ARGV.output;
        }
    }
} catch (error) {
    // @ts-ignore
    throw new Error(error);
}

const LvInfos = [];

LvInfos.push(_parseNumber(ARGV.Lv0));

if (ARGV.Lv1) {
    LvInfos.push(_parseNumber(ARGV.Lv1));
}

if (ARGV.Lv2 && !ARGV.Lv1) {
    console.log(`error: Can't have Lv2 without Lv1 offset.`);

    process.exit(0);
}

if (ARGV.Lv2) {
    LvInfos.push(_parseNumber(ARGV.Lv2));
}

if (ARGV.Lv3 && !ARGV.Lv2) {
    console.log(`error: Can't have Lv3 without Lv2 offset.`);

    process.exit(0);
}

if (ARGV.Lv3) {
    LvInfos.push(_parseNumber(ARGV.Lv3));
}

if (ARGV.Lv4 && !ARGV.Lv3) {
    console.log(`error: Can't have Lv4 without Lv3 offset.`);

    process.exit(0);
}

if (ARGV.Lv4) {
    LvInfos.push(_parseNumber(ARGV.Lv4));
}

// #region Code Starts

/**
 * @type {Buffer<ArrayBufferLike>}
 */
var MASTER_ELF_DATA;

try {
    MASTER_ELF_DATA = FS.readFile(INPUT_LIB_PATH);
} catch (error) {
    // @ts-ignore
    throw new Error(error);
}

/**
 * @type {Buffer}
 */
var LAST_ELF;

/**
 * @type {Buffer}
 */
var CURRENT_ELF;

var completeled = true;

for (let i = 0; i < LvInfos.length; i++) {
    const LvInfo = LvInfos[i];

    if(i == 0){
        CURRENT_ELF = MASTER_ELF_DATA;
    } else {
        // @ts-ignore
        CURRENT_ELF = LAST_ELF;
    }

    if(LvInfo > CURRENT_ELF.byteLength){
        throw new Error(`Lv${i} info outside of data size. ${LvInfo} > ${CURRENT_ELF.byteLength}`);
    }

    const LvData = readLvInfo(CURRENT_ELF, LvInfo);

    if(LvData.NextLvInfo != LvInfo){
        throw new Error("Error: LvInfo didn't pass check.");
    }

    var masterLibName = `${INPUT_LIB_NAME}_Lv${i}_${LvData.masterElfSize}.so`;

    const ElfChunk = MASTER_ELF_DATA.subarray(LvData.elfchunkOffset, LvData.elfchunkOffset + LvData.elfchunkSize);

    const CONTROLLER_ELF_BUFFER = Buffer.alloc(LvData.masterElfSize);

    decodeELF(ElfChunk, CONTROLLER_ELF_BUFFER);

    console.log(`✅ Creating ${masterLibName}`);

    FS.writeFile(CONTROLLER_ELF_BUFFER, path.join(OUTPUT_PATH, masterLibName));
    // now tables
    for (let z = 0; z < (LvData.tableSize / TABLE_ENTRY_SIZE) >>> 0; z++) {
        const off = LvData.tableOffset + (z * TABLE_ENTRY_SIZE);

        const tableData = readTableEntry(MASTER_ELF_DATA, off);

        console.log(tableData);

        var libTableName = tableData.name;

        if(tableData.name == ""){
            libTableName = `${INPUT_LIB_NAME}_Lv${i}_type${tableData.type}_${tableData.offsetWithinMaster}.so`;
        }

        const chunktable = MASTER_ELF_DATA.subarray(tableData.offsetWithinMaster, tableData.offsetWithinMaster + tableData.sizeWithinMaster);

        var dstTable = Buffer.alloc(tableData.distSize);

        decodeELF(chunktable, dstTable);

        if(tableData.type == 241){
            const offsets = praseELF32(MASTER_ELF_DATA);

            const replacementData = read241(dstTable);

            replacementData.symbolData.copy(MASTER_ELF_DATA, offsets.DT_SYMTAB, 0);

            replacementData.stringData.copy(MASTER_ELF_DATA, offsets.DT_STRTAB, 0);
        }

        if(tableData.type == 248){
            decodeELF(dstTable, MASTER_ELF_DATA);
        }

        console.log(`✅ Creating ${libTableName}`);

        FS.writeFile(dstTable, path.join(OUTPUT_PATH, libTableName));
    }

    LAST_ELF = CONTROLLER_ELF_BUFFER;
}

if(completeled){
    try {
        FS.writeFile(MASTER_ELF_DATA, path.join(OUTPUT_PATH, INPUT_LIB_NAME + "_decryptred.so"));

        console.log(`✅ Created ${INPUT_LIB_NAME + "_decrypted.so"}`);
    } catch (error) {
        // @ts-ignore
        throw new Error(error);
    }
}

    