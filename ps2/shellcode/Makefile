TOOLCHAIN_BIN = /usr/local/ps2dev/ee/bin
PREFIX = mips64r5900el-ps2-elf-
CC = $(TOOLCHAIN_BIN)/$(PREFIX)gcc
OBJCOPY = $(TOOLCHAIN_BIN)/$(PREFIX)objcopy
PS2SDK ?= /usr/local/ps2dev/ps2sdk

CFLAGS = -D_EE -O0 -G0 -Wall -fno-pic -mno-abicalls \
         -I$(PS2SDK)/ee/include -I$(PS2SDK)/common/include
LDFLAGS = -nostartfiles -nostdlib -T shellcode.ld -L$(PS2SDK)/ee/lib
LIBS = -lc

all: shellcode.bin

shellcode.elf: start.s shellcode.c
	$(CC) $(CFLAGS) $(LDFLAGS) start.s shellcode.c -o $@ $(LIBS)

shellcode.bin: shellcode.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f shellcode.elf shellcode.bin

.PHONY: all clean
