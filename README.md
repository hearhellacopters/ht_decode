# ht_decode

`ht_decode` is a research project focused on understanding, documenting and recreating a native Android library protection system used in commercial applications. It stripes the native library down into a series of levels performing anti-vm / anti-debug / anti-cheat checks before recreating the real library at runtime. A full breakdown of all researched systems can be found [here](/libs/README.md). 

The provided Node.js command-line app is meant for reverse engineers between __`experienced`__ to __`expert`__ understanding to acquire the needed data to use it. It supports current builds of this unpacker as well as [Legacy](#legacy) versions and a [data1.dat](#data1dat) decoder. Also included is a [string decoder](#string-decoder) (supports Legacy as well).

**Note: This software does NOT remove the protection from the application, produce a modified APK, or generate a drop-in replacement library suitable for deployment. Instead, it recreates the library and associated metadata in a form that can be examined at each stage using static reverse engineering tools such as IDA Pro and Ghidra.**

# Command-line

Unlike the simpler [Legacy](#legacy) version of this unpacker (pre-2020), more command-lines offsets are needed for recreating the ELF.

The software works in stages. So entering Lv0's offset will produce ELFs (*this version they don't have names so they are numbered as "type"*) to Lv1 and then you will need the next offsets found in Lv1. You will have to repeat this process until at Lv7.

The first offset you will need is the offset within the **SHT_LOUSER** section of the library that the first level is created from. In my experience, this has always been `572` (the default value) bytes in, but could be different in other builds so you can set it with the `--LOUSER_START` command. You can verify this by following the start up logic until you hit a function that ends with a value being both subtracted and added to a structure before finishing.

![lv](/img/LOUSER.png)

After that you will need offsets to both an AES table and a PRNG seed found in each Lv library. The AES table can normally be identified by two short values of 256 and 15 following by a block of 60 ints. The seed value can usually be found before or after this block.

![seed](/img/seed_aes.png)

You will follow this pattern until you hit the 5th level where it will generate a Lv6 and Lv7 as well. In this version of the software, Lv6 is the library that recreates the master library. *There is one more level (Lv8) but it just wraps up the process.* 

You will need up to 2 additional offsets depending on the version of the unpacker and bit version of the library (64 bit libraries don't appear to have a jump table. You will know if there are jump tables used if this level produces a "type194" and "type195" library and the jump table section of Lv6 isn't blank). There is an addition table used that has it's own `table_seed` value, this value can normally be found right before the offset table for splitting the jump table (this area will be blank if the unpacker doesn't use one) but is again normally found around the AES table at the bottom of the library. The jump table `offsets` splits needs the offset to the split count (NOT the offset to the start of the table).

Once you have all 4 of these offsets, the final master library will be recreated as well as a python script for IDA Pro to add any missing function names.

![lv6](/img/lv6.png)

_Note: All input numerical values can be in decimal or hex (starting with `0x`)_

Example:

```
node app.js --file ./libs/lib__57d5__.so -l 572 -o ./output -s0 0x128B0 -e0 0x128B4 -s1 0x82D4 -e1 0x81D4 -s2 0x82DC -e2 0x81DC -s3 0x82DC -e3 0x81DC -s4 0x82DC -e4 0x81DC -s5 0x82DC -e5 0x81DC -s6 0xB37C -e6 0xB27C -t6 0xB1F0 -o6 0xB1F4 -s7 0x82DC -e7 0x81DC
```

| Command-line             | Type      | Description                                |
| :---                    | :---:     | :---                                |
| `-f, --file`            | `string`  | (Required) Location of the library file |
| `-o, --output`          | `string`  | Location of for the decompiled libraries (defaults to input folder) |
| `-l, --LOUSER_START`    | `string`  | Offset within the LOUSER data of the master library to start (default 572) |
| `-e0, --aes_table0`     | `string`  | Offset within the libLv0.so created to the encryption table. Can be in hex or decimal. |
| `-s0, --seed0`          | `string`  | Offset within the libLv0.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e1, --aes_table1`     | `string`  | Offset within the libLv1.so created to the encryption table. Can be in hex or decimal. |
| `-s1, --seed1`          | `string`  | Offset within the libLv1.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e2, --aes_table2`     | `string`  | Offset within the libLv2.so created to the encryption table. Can be in hex or decimal. |
| `-s2, --seed2`          | `string`  | Offset within the libLv2.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e3, --aes_table3`     | `string`  | Offset within the libLv3.so created to the encryption table. Can be in hex or decimal. |
| `-s3, --seed3`          | `string`  | Offset within the libLv3.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e4, --aes_table4`     | `string`  | Offset within the libLv4.so created to the encryption table. Can be in hex or decimal. |
| `-s4, --seed4`          | `string`  | Offset within the libLv4.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e5, --aes_table5`     | `string`  | Offset within the libLv5.so created to the encryption table. Can be in hex or decimal. |
| `-s5, --seed5`          | `string`  | Offset within the libLv5.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-e6, --aes_table6`     | `string`  | Offset within the libLv6.so created to the encryption table. Can be in hex or decimal. |
| `-s6, --seed6`          | `string`  | Offset within the libLv6.so to the seed value used in decoding the next level. Can be in hex or decimal. |
| `-t6, --seed_table6`    | `string`  | Offset within the libLv6.so to the seed value used in creating the tables for the master library. (can be in hex or decimal). |
| `-o6, --offsets6`       | `string`  | Offset within the libLv6.so to the count of offset sections used in creating the master library jump tables (only in 32 bit libraries). (can be in hex or decimal). |
| `-e7, --aes_table7`     | `string`  | Offset within the libLv7.so created to the encryption table. Can be in hex or decimal. |
| `-s7, --seed7`          | `string`  | Offset within the libLv7.so to the seed value used in decoding the next level. Can be in hex or decimal. |

# Legacy

Legacy ELFs (likely used before 2020) can be identified by an embedded "NextLvInfo" structure. When examining the library, you'll find a function that simply returns an address to a 17 int structure that ends with the starting address of the structure. The **offset** to the start of this structure is what you will need for each level.

The software works in stages. So entering Lv0's offset will produce ELFs to Lv1 and then you will need the next offset found in Lv1. You will need to repeat this process until at Lv3. 

![lv](/img/nextLv.png)

_Note: All input numerical values can be in decimal or hex (starting with `0x`)_

Example:

```
node app.js --file ./libs/lib__57d5__legacy.so -o ./output -y --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C
```

| Command-line             | Type      | Description                                |
| :---                    | :---:     | :---                                |
||Legacy||
| `-f, --file`            | `string`  | (Required) Location of the library file |
| `-y, --legacy`          | `boolean` | (Required) For libraries older than 2020 (only 32 bit), try running legacy mode if decode failed. |
| `-o, --output`          | `string`  | Location of for the decompiled libraries (defaults to input folder) |
| `-0, --Lv0`             | `string`  | (Required) Offset of the Lv0 structure within the master library. Can be in hex or decimal. |
| `-1, --Lv1`             | `string`  | Offset of the Lv1 structure within the Lv0 library created. Can be in hex or decimal. |
| `-2, --Lv2`             | `string`  | Offset of the Lv2 structure within the Lv1 library created. Can be in hex or decimal. |
| `-3, --Lv3`             | `string`  | Offset of the Lv3 structure within the Lv2 library created. Can be in hex or decimal. |

# data1.dat

Depending on how deep you want to go, and the type of unpacker the library was built with, you can sometimes find a `data1.dat` inside the APK. This file isn't used in recreating the master library but contains hashes and other ELFs used in the process. You can likely find references to the file in the non-Lv# libraries that get decompiled. While I have default seed values for each section, you can enter them in pairs if you find others.

Example:

```
node app.js --file ./libs/data1.dat -o ./output -d --id 4 5 7 8 128 129 136 137 132 133 --seeds 0xCC29E208 0xF684A9 0x97045CC 0x709ACA1D 0xF86CFF96 0x2D800665 0xE788FB20 0xDAC08FCD 0x03D2270F 0x01BF26DA
```

| Command-line             | Type      | Description                                |
| :---                    | :---:     | :---                                |
||data1.dat||
| `-d, --data1`          | `boolean` | (Required) The input file is a data1.dat file for decoding. |
| `-i, --id`             | `string[]`  | Array of data1.dat entry ids to match with seeds. |
| `-s, --seeds `         | `string[]`  | Array of data1.dat seeds to match with ids (can be in hex or decimal). |

# String Decoder

If you are reversing some of the decompiled ELFs and want to quickly decode the encoded strings, I exposed the function below. If decompiling a legacy ELF, use the `--legacy` flag.

_Note: All input numerical values can be in decimal or hex (starting with `0x`)_

Example:

```bash
node app.js -r D65C76DC7C748684B4E476BE648EC6C4 # %s/app-lib/%s-%d
```

| Command-line             | Type      | Description                                |
| :---                    | :---:     | :---                                |
||String Decoder||
| `-r, --decodestring`          | `string[]` | Hex strings to decode (use the --legacy for legacy coded strings). |
| `-y, --legacy`          | `boolean` | If the string is from a library older than 2020 (only 32 bit). |

For more info, read the [readme](/libs/README.md) here. As well as the 010 Binary Templates in the [bt](/bt/) folder.