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
        throw new Error("Can not find folder to file being read: " + srcPath);
    }

    if (!_fileExists(srcPath)) {
        throw new Error("Can not find file being read: " + srcPath);
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
        // @ts-ignore
        throw new Error("Error checking path to write data. " + targetPath);
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
    if (typeof data == "string" || !Buffer.isBuffer(data)) {
        data = JSON.stringify(data);
    }

    if (Buffer.isBuffer(data) || typeof data == "string") {
        _ensurePathExists(srcPath, data);
    } else {
        throw new Error("Data supplied can not be written. " + srcPath);
    }
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
}

module.exports = {
    FS
};