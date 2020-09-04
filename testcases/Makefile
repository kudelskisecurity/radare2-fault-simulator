RISCV_CC=/home/sylvain/software/riscv64-unknown-elf-gcc-8.3.0-2020.04.1-x86_64-linux-ubuntu14/bin/riscv64-unknown-elf-gcc
RISCV_CFLAGS=-march=rv32ima -mabi=ilp32
RISCV_CFLAGSCOMPRESS=-march=rv32imac -mabi=ilp32

aes_riscv_compress.elf: test_aes.c aes.c
	$(RISCV_CC) test_aes.c aes.c -o aes_riscv_compress.elf $(RISCV_CFLAGSCOMPRESS)

aes_riscv_no_compress.elf: test_aes.c aes.c
	$(RISCV_CC) test_aes.c aes.c -o aes_riscv_no_compress.elf $(RISCV_CFLAGS)

check1_x64.elf: target.c
	gcc target.c -g -o check1_x64.elf

clean:
	rm -vf *.o  aes_riscv_no_compress.elf aes_riscv_compress.elf check1_x64.elf
