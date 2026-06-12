CFLAGS="-I../ -I../../ -DLOCALOPTIONS_H_EXISTS -DLTC_EASY -mlongcalls"
cp Makefile.dropbear dropbear/Makefile
cp Makefile.libtomcrypt dropbear/libtomcrypt/Makefile
cp Makefile.libtommath dropbear/libtommath/Makefile
make -C dropbear/libtomcrypt CC=xtensa-esp32-elf-gcc RANLIB=xtensa-esp32-elf-ranlib AR=xtensa-esp32-elf-ar CFLAGS="$CFLAGS" clean libtomcrypt.a
make -C dropbear/libtommath CC=xtensa-esp32-elf-gcc RANLIB=xtensa-esp32-elf-ranlib AR=xtensa-esp32-elf-ar CFLAGS="$CFLAGS"  clean libtommath.a
