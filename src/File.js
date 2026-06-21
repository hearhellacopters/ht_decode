// @ts-check

const fs = require('fs');
const path = require("path");

/**
 * Check if a file exist.
 * 
 * @param {string} filePath Path to file to check.
 * @returns {boolean} if exists
 */
function _fileExists(filePath) {
    try {
        fs.accessSync(filePath, fs.constants.F_OK);

        return true;  // File exists
    } catch (error) {
        // @ts-ignore
        if (error.code === 'ENOENT') {
            return false;  // File does not exist
        } else {
            console.error(error); // Other errors

            return false;
        }
    }
};

/**
 * Loads a file and returns the ``Buffer``.
 * 
 * @param {string} srcPath 
 * @returns {Buffer}
 */
function _readFile(srcPath) {
    const dir = path.dirname(srcPath);

    if (!_directoryExists(dir)) {
        console.log("Can not find folder to file being read: " + srcPath);

        process.exit(0);
    }

    if (!_fileExists(srcPath)) {
        console.log("Can not find file being read: " + srcPath);

        process.exit(0);
    }

    return fs.readFileSync(srcPath);
};

/**
 * Ensures that a given path exists as a file or directory.
 * 
 * Will write data if passed.
 * 
 * @param {string} targetPath The path to check or create.
 * @param {any?} fileData Data for the file
 */
function _ensurePathExists(targetPath, fileData) {
    const isFile = !!path.extname(targetPath);

    try {
        if (fs.existsSync(targetPath)) {
            const stats = fs.statSync(targetPath);
            // Path already exists as file, but we want folder
            if (!isFile && stats.isFile()) {
                fs.mkdirSync(targetPath, { recursive: true });

                return;
            }
        }
        // Path does not exist, create it
        if (!isFile) {
            // targetPath is a folder so create it
            fs.mkdirSync(targetPath, { recursive: true });
        } else if (isFile) {
            // targetPath is a file so make sure folder path is created
            const dir = path.dirname(targetPath);

            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }

            if (fileData) {
                // writes file data if supplied
                fs.writeFileSync(targetPath, fileData);
            }
        }
    } catch (err) {
        console.log("[!] Error checking path to write data. " + targetPath);

        console.log(err);

        process.exit(0);
    }
};

/**
 * Writes a file. Will create the directory if it doesn't exist.
 * 
 * @param {Buffer|string|object} data File data
 * @param {string} srcPath Full path to file including the file name.
 * @throws {Error} if data is not writable.
 */
function _writeFile(data, srcPath) {
    // stringify if needed
    if (typeof data != "string") {
        if(!Buffer.isBuffer(data)){
            data = JSON.stringify(data);
        }
    }

    if (Buffer.isBuffer(data) || typeof data == "string") {
        _ensurePathExists(srcPath, data);
    } else {
        console.log("Data supplied can not be written. " + srcPath);

        process.exit(0);
    }
};

/**
 * Hex dumps a Buffer or Uint8Array and returns a string.
 * 
 * Mostly for debugging. Default options below.
 * 
 *  ```javascript
 *  options = {
 *       length: 192, // number of bytes to log, default 192 or less
 *       startByte: 0, // byte to start dump (default 0)
 *       supressUnicode: true // disables unicode character preview for even columns
 *   }
 * ```
 * 
 * @param {Uint8Array|Buffer} src Uint8Array or Buffer
 * @param {{length?:number|undefined,startByte?:number|undefined,supressUnicode?:boolean|undefined}|undefined} options hex dump options
 * @returns {string} string
 */
function hexdump(src, options = {}) {
    var length = options && options.length;

    var startByte = options && options.startByte;

    var supressUnicode = options && options.supressUnicode || true;

    const start = startByte || 0;

    const end = Math.min(start + (length || 192), src.length);
    /**
     * hex checks the hex
     * @param {number} byte to read
     * @param {number} bits to read
     * @returns {number} number
     */
    function hex_check(byte, bits) {
        var value = 0;

        for (var i = 0; i < bits;) {
            var remaining = bits - i;

            var bitOffset = 0;

            var currentByte = byte;

            var read = Math.min(remaining, 8 - bitOffset);

            var mask, readBits;

            mask = ~(0xFF << read);

            readBits = (currentByte >> (8 - read - bitOffset)) & mask;

            value <<= read;

            value |= readBits;

            i += read;
        }

        value = value >>> 0;

        return value;
    }
    /**
     * @type {string[]}
     */
    const rows = [];

    var header = "   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  ";

    var ending = "0123456789ABCDEF";

    var addr = "";

    for (let i = start; i < end; i += 16) {
        addr = i.toString(16).padStart(5, '0');

        var row = src?.slice(i, i + 16) || [];

        var hex = Array.from(row, (byte) => byte.toString(16).padStart(2, '0')).join(' ');

        rows.push(`${addr}  ${hex.padEnd(47)}  `);
    }

    let result = '';

    let make_wide = false;

    let i = start;

    while (i < end) {
        const byte = src[i];

        if (byte < 32 || byte == 127) {
            result += '.';
        } else if (byte < 127) {
            // Valid UTF-8 start byte or single-byte character
            // Convert the byte to a character and add it to the result
            result += String.fromCharCode(byte);
        } else if (supressUnicode) {
            result += '.';
        } else if (hex_check(byte, 1) == 0) {
            //Byte 1
            result += String.fromCharCode(byte);
        } else if (hex_check(byte, 3) == 6) {
            //Byte 2
            if (i + 1 <= end) {
                //check second byte
                const byte2 = src[i + 1];
                if (hex_check(byte2, 2) == 2) {
                    const charCode = ((byte & 0x1f) << 6) | (byte2 & 0x3f);

                    i++;

                    make_wide = true;

                    const read = " " + String.fromCharCode(charCode);

                    result += read;
                } else {
                    result += ".";
                }
            } else {
                result += ".";
            }
        } else if (hex_check(byte, 4) == 14) {
            //Byte 3
            if (i + 1 <= end) {
                //check second byte
                const byte2 = src[i + 1];

                if (hex_check(byte2, 2) == 2) {
                    if (i + 2 <= end) {
                        //check third byte
                        const byte3 = src[i + 2];

                        if (hex_check(byte3, 2) == 2) {
                            const charCode = ((byte & 0x0f) << 12) |
                                ((byte2 & 0x3f) << 6) |
                                (byte3 & 0x3f);

                            i += 2;

                            make_wide = true;

                            const read = "  " + String.fromCharCode(charCode);

                            result += read;
                        } else {
                            i++;

                            result += " .";
                        }
                    } else {
                        i++;

                        result += " .";
                    }
                } else {
                    result += ".";
                }
            } else {
                result += ".";
            }
        } else if (hex_check(byte, 5) == 28) {
            //Byte 4
            if (i + 1 <= end) {
                //check second byte
                const byte2 = src[i + 1];

                if (hex_check(byte2, 2) == 2) {
                    if (i + 2 <= end) {
                        //check third byte
                        const byte3 = src[i + 2];

                        if (hex_check(byte3, 2) == 2) {
                            if (i + 3 <= end) {
                                //check fourth byte
                                const byte4 = src[i + 2];

                                if (hex_check(byte4, 2) == 2) {
                                    const charCode = (((byte4 & 0xFF) << 24) | ((byte3 & 0xFF) << 16) | ((byte2 & 0xFF) << 8) | (byte & 0xFF));

                                    i += 3;

                                    make_wide = true;

                                    const read = "   " + String.fromCharCode(charCode);

                                    result += read;
                                } else {
                                    i += 2;

                                    result += "  .";
                                }
                            } else {
                                i += 2;
                                result += "  .";
                            }
                        }
                        else {
                            i++;
                            result += " .";
                        }
                    } else {
                        i++;
                        result += " .";
                    }
                } else {
                    result += ".";
                }
            } else {
                result += ".";
            }
        } else {
            // Invalid UTF-8 byte, add a period to the result
            result += '.';
        }

        i++;
    }

    const chunks = result.match(new RegExp(`.{1,${16}}`, 'g'));

    chunks?.forEach((self, i) => {
        rows[i] = rows[i] + (make_wide ? "|" + self + "|" : self);
    });

    header = "".padStart(addr.length) + header + (make_wide ? "" : ending);

    rows.unshift(header);

    if (make_wide) {
        rows.push("*Removed character byte header on unicode detection");
    }

    return (rows.join("\n"));
};

/**
 * Check if a directory exist.
 * 
 * @param {string} dir Path to directory.
 * @returns {boolean} if exists
 */
function _directoryExists(dir) {
    if (fs.existsSync(dir)) {
        return true;
    };

    return false;
};

/**
 * Creates a directory.
 * 
 * @param {string} dir Path to directory.
 */
function _makeDirectory(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    };
};

/**
 * General file system static class.
 * 
 * For all file based operations.
 * @class
 */
class FS {
    /**
     * Test if a directory exists.
     * 
     * @param {string} srcPath Path to test. Do NOT include a file name.
     * @returns {boolean} if directory exists.
     */
    static directoryExists(srcPath) {
        return _directoryExists(srcPath);
    };

    /**
     * Test if a file directory exists.
     * 
     * @param {string} srcPath Full path to file including the file name.
     * @returns {boolean} if file exists.
     */
    static fileExists(srcPath) {
        return _fileExists(srcPath);
    };

    /**
     * Creates a path if one doesn't exist.
     * 
     * @param {string} srcPath Path to create. Do NOT include a file name.
     */
    static createDirectory(srcPath) {
        if (!_directoryExists(srcPath)) {
            _makeDirectory(srcPath);
        }
    };

    /**
     * Writes a file. Will create the directory if it doesn't exist.
     * 
     * @param {Buffer|string|object} data File data
     * @param {string} srcPath Full path to file including the file name.
     * @throws {Error} if data is not writable.
     */
    static writeFile(data, srcPath) {
        _writeFile(data, srcPath);
    };

    /**
     * Loads a file and returns the ``Buffer``.
     * 
     * @param {string} srcPath Full path to file including the file name.
     * 
     * @throws {Error} if file doesn't exist
     */
    static readFile(srcPath) {
        return _readFile(srcPath);
    };

    /**
     * Hex dumps a Buffer or Uint8Array and returns a string.
     * 
     * Mostly for debugging. Default options below.
     * 
     *  ```javascript
     *  options = {
     *       length: 192, // number of bytes to log, default 192 or less
     *       startByte: 0, // byte to start dump (default 0)
     *       supressUnicode: true // disables unicode character preview for even columns
     *   }
     * ```
     * 
     * @param {Uint8Array|Buffer} src Uint8Array or Buffer
     * @param {{length?:number|undefined,startByte?:number|undefined,supressUnicode?:boolean|undefined}|undefined} options hex dump options
     */
    static hexdump(src, options = {}) {
        const dump = hexdump(src, options)

        console.log(dump);

        return dump;
    }

    /**
     * 
     * @param {number} number 
     */
    static makeOffset(number){
        return "0x" + number.toString(16);
    };
}

module.exports = {
    FS
};