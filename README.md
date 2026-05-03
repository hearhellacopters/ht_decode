# ht_decode

A commandline Node.js app for decoding and recompiling an anti-vm / anti-debug lib. The program breaks down all libs that are packed as well as applies stripped symbols, string and programming to the orginal.

Run as node app with:

`node app.js --file ./libs/lib__57d5__.so --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C`

| Commandline        | Type      | Desc                                |
| :---               | :---:     | :---                                |
| `-f, --file`       | `string`  | (Required) Location of the lib file |
| `-0, --Lv0`        | `string`  | (Required) The location of the Lv0 structure within the file. (can be in hex or decimal) |
| `-o, --output`     | `string`  | Location of for the decompiled lib files (defaults to input folder) |
| `-1, --Lv1`        | `string`  | The location of the Lv1 structure within the last lib created. (can be in hex or decimal) |
| `-2, --Lv2`        | `string`  | The location of the Lv2 structure within the last lib created. (can be in hex or decimal) |
| `-3, --Lv3`        | `string`  | The location of the Lv3 structure within the last lib created. (can be in hex or decimal) |
| `-4, --Lv4`        | `string`  | The location of the Lv4 structure within the last lib created. (can be in hex or decimal) |

To find the Lv info, load the master lib in a decompiler and look for a function that returns just an offset. The offset is to a stuture that ends with the offset of the start of the stuture (normally `0x44` bytes). The offset to each level within the master lib can be found in the created Lv# libs, normally label `get_NextLvInfo`.

Or from the built exe

`ht_decode.exe --file ./libs/lib__57d5__.so --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C`

For more info, read the [readme](/libs/README.md) here. As well as the 010 Binary Templates in the `bt` folder. 

- Note: Only works on ARM32 at the moment. More research is needed for ARM64.