/**
 * @file for creating an executable .exe file for windows.
 */

const exe = require("@hearhellacopters/exe");
const package = require('./package.json');

const build = exe({
  entry: "./app.js",
  out: `./${package.name}.exe`,
  pkg: ["-C", "GZip"], // Specify extra pkg arguments
  version: package.version,
  target: "node24-win-x64",
  icon: "./app.ico", // Application icons must be same size as prebuild target
  //executionLevel: "highestAvailable",
  properties: {
    FileDescription: package.description,
    ProductName: package.name,
    OriginalFilename: `${package.name}.exe`,
    LegalCopyright: "MIT"
  }
});

build.then(() => console.log("Windows build completed!"));