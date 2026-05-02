# ht_decode

A commandline Node.js app for decoding and recompiling an anti-vm / anti-debug lib. The program breaks down all libs that are packed as well as applies stripped symbols, string and programming to the orginal.

Run as node app with:

`node app.js --file ./libs/lib__57d5__.so --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C`

Or from the built exe

`ht_decode.exe --file ./libs/lib__57d5__.so --Lv0 0x15AC --Lv1 0x1C50 --Lv2 0x1C0C --Lv3 0x1C0C`

For more info, read the [readme](/libs/README.md) here. As well as the 010 Binary Templates in the `bt` folder. 

- Note: Only works on ARM32 at the moment. More research is needed for ARM64.