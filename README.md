# [Exynos BootROM dump tool](https://github.com/frederic/exynos-bootrom-dump)

# [announce](https://fredericb.info)

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