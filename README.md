# ht_decode

A commandline Node.js app for decoding and recompiling an anti-vm / anti-debug lib Android unpacker. The program breaks down all libraries that are packed as well as applies stripped symbols, string and programming to the orginal.

Run as node app with:

Modern

`node app.js --file ./libs/lib__57d5__.so --output ./ouptut --LOUSER_START 0x23C --encrpytion_table 0x128B4`

Legacy

`node app.js --file ./libs/lib__57d5__.so --output ./ouptut --legacy --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C`

| Commandline             | Type      | Desc                                |
| :---                    | :---:     | :---                                |
||Modern||
| `-f, --file`            | `string`  | (Required) Location of the library file |
| `-o, --output`          | `string`  | Location of for the decompiled libraries (defaults to input folder) |
| `-l, --LOUSER_START`    | `string`  | Offset within the LOUSER data of the master library to start (default 572) |
| `-e0, --aes_table0`     | `string`  | Offset within the libLv0.so created to the ecryption table. Can be in hex or decimal. |
| `-s0, --seed0`          | `string`  | Offset within the libLv0.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e1, --aes_table1`     | `string`  | Offset within the libLv1.so created to the ecryption table. Can be in hex or decimal. |
| `-s1, --seed1`          | `string`  | Offset within the libLv1.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e2, --aes_table2`     | `string`  | Offset within the libLv2.so created to the ecryption table. Can be in hex or decimal. |
| `-s2, --seed2`          | `string`  | Offset within the libLv2.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e3, --aes_table3`     | `string`  | Offset within the libLv3.so created to the ecryption table. Can be in hex or decimal. |
| `-s3, --seed3`          | `string`  | Offset within the libLv3.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e4, --aes_table4`     | `string`  | Offset within the libLv4.so created to the ecryption table. Can be in hex or decimal. |
| `-s4, --seed4`          | `string`  | Offset within the libLv4.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e5, --aes_table5`     | `string`  | Offset within the libLv5.so created to the ecryption table. Can be in hex or decimal. |
| `-s5, --seed5`          | `string`  | Offset within the libLv5.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e6, --aes_table6`     | `string`  | Offset within the libLv6.so created to the ecryption table. Can be in hex or decimal. |
| `-s6, --seed6`          | `string`  | Offset within the libLv6.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-t6, --seed_table6`    | `string`  | Offset within the libLv6.so to the seed value used in creating the tables for the master library. (can be in hex or decimal). |
| `-o6, --offsets6`       | `string`  | Offset within the libLv6.so to the count of offset sections used in creating the master library (only in 32 bit libs). (can be in hex or decimal). |
| `-e7, --aes_table7`     | `string`  | Offset within the libLv7.so created to the ecryption table. Can be in hex or decimal. |
| `-s7, --seed7`          | `string`  | Offset within the libLv7.so to the seed value used in decoding the next level. Can be in hex or decimal. |
||data1.dat||
| `-d, --data1`          | `boolean` | (Required) The input file is a data1.dat file for decoding. |
| `-i, --id`             | `string[]`  | Array of data1.dat entry ids to match with seeds. |
| `-s, --seeds `         | `string[]`  | Array of data1.dat seeds to match with ids (can be in hex or decimal). |
||Legacy||
| `-y, --legacy`          | `boolean` | (Required) For libraries older than 2023 (only 32 bit), try running legacy mode if decode failed. |
| `-0, --Lv0`             | `string`  | (Required) Offset of the Lv0 structure within the master library. Can be in hex or decimal. |
| `-1, --Lv1`             | `string`  | Offset of the Lv1 structure within the Lv0 library created. Can be in hex or decimal. |
| `-2, --Lv2`             | `string`  | Offset of the Lv2 structure within the Lv1 library created. Can be in hex or decimal. |
| `-3, --Lv3`             | `string`  | Offset of the Lv3 structure within the Lv2 library created. Can be in hex or decimal. |

To find the Lv info, load the master library in a decompiler and look for a function that returns just an offset. The offset is to a stuture that ends with the offset of the start of the stuture (normally `0x44` bytes). The offset to each level within the master lib can be found in the created Lv# libs, normally label `get_NextLvInfo`.

Or from the built exe

`ht_decode.exe --legacy --file ./libs/lib__57d5__legacy.so --output ./ouptut --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C`

For more info, read the [readme](/libs/README.md) here. As well as the 010 Binary Templates in the `bt` folder.