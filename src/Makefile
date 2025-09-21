CC = gcc
SRC = target.c
OBJ = target
LIBC_PATH ?= /lib/x86_64-linux-gnu
LD ?= /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

CFLAGS = -nostdlib -no-pie -nostartfiles -Wl,--dynamic-linker=${LD} -L${LIBC_PATH} -lc \
		 -Xlinker -rpath=${LIBC_PATH} -Xlinker -I${LD}

all:
	${CC} -o ../${OBJ} ${SRC} ${CFLAGS}

clean:
	@rm -f ../${OBJ}