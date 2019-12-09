# [Exynos 8890 BootROM dump tool](https://github.com/frederic/exynos8890-bootrom-dump)
This tool allows to dump the Exynos 8890 bootROM from a Samsung Galaxy S7 phone by exploiting two trustzone vulnerabilities.

# [description](https://fredericb.info)

# target
Samsung Galaxy S7 (G930F) - G930FXXU2DRD1 - root/SU enabled

# setup
```
$ adb pull /system/vendor/lib/libMcClient.so .
$ adb pull /system/app/mcRegistry/ffffffffd00000000000000000000004.tlbin ffffffffd00000000000000000000004.tlbin.backup
$ adb push ./G930FXXU1DQAN_fffffffff0000000000000000000001b.tlbin /data/local/tmp/
$ adb push ./G930FXXU1APB4_ffffffffd00000000000000000000004.tlbin /data/local/tmp/
$ adb shell "su -c mount -o rw,remount /system"
$ adb shell "su cp /data/local/tmp/G930FXXU1APB4_ffffffffd00000000000000000000004.tlbin /system/app/mcRegistry/ffffffffd00000000000000000000004.tlbin"
$ adb shell "su -c mount -o ro,remount /system"
```
# build
```
$ ~/tools/android/android-ndk-r20/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang ./g930f_dump-bootrom.c -L./ -lMcClient -o g930f_dump-bootrom
$ adb push ./g930f_dump-bootrom /data/local/tmp/
```

# usage
Dump size is 0x1000 bytes. Read address is specified in argument:
```
herolte:/data/local/tmp # ./g930f_dump-bootrom 0
[+] Address in TA virtual memory : 0x200000 (0xa000 bytes)
Dumped to file dump_0x0.bin
BB0038D57B0F78927F0300F141000054FC7F83147BFF48D3FD031EAAC9640094FC0314AA74070058940240B97407005814C01ED5740700589F0200B91D650094A2600094DD650094D0630094556400945640A0D2150080D27F0300F141000054950080D2B5021C8BD40A158BBF0217EB41940C545F111ED599050058390340B9390300123F07007161000054B764009402000014CD640094C0040058E9640094C2040058430040B97F00067241000054B2600094600400581F00009160040058950000946004005881040058A30400581F0001EBC00000543F0003EB80000054024440B8224400B8FCFFFF17E1030[...]
```