TARGET := dtts

ifeq ($(strip $(V)),)
	E := @echo
	Q := @
else
	E = @\#
	Q =
endif

CC := $(CROSS_COMPILE)gcc

CFLAGS := -std=gnu99 -Wall -Wextra \
	-I./dtt/include \
	-I./common/include \
	-I./include

LDFLAGS := -lpthread -lrt \
	-L./dtt/lib -l:libdtt.a \
	-L./common -l:libcommon.a

ifeq ($(strip $(DEBUG)),)
	CFLAGS += -O2
	LDFLAGS += -s  # strip
else
	CFLAGS += -O0 -g -DDEBUG
endif

SRC_ALL := $(shell find . -name "*.c" -o -name "*.h")

SRC += node.c
SRC += cluster.c
SRC += file.c
SRC += memory.c
SRC += task.c
SRC += dtts.c

OBJ := $(SRC:.c=.o)

all: dttcli $(TARGET) example

deb: dttcli $(TARGET)
	bash build-aux/build-deb.sh

rpm: dttcli $(TARGET)
	bash build-aux/build-rpm.sh

$(TARGET): $(OBJ)
	$(Q) echo "  LD      " $@
	$(Q) $(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(Q) echo "  CC      " $@
	$(Q) $(CC) $(CFLAGS) -c -o $@ $<
	$(Q) echo "savedcmd_$@ := $(CC) $(CFLAGS) -c -o $@ $<" > .$(@F).cmd

dttcli: libdtt
	$(Q) make -C dtt-cli --no-print-directory

example: libdtt
	$(Q) make -C dtt --no-print-directory
	$(Q) make -C examples --no-print-directory

libdtt: libcommon
	$(Q) make -C dtt --no-print-directory

libcommon:
	$(Q) make -C common --no-print-directory

unittest:
	$(Q) make -C test run

tags: ${SRC_ALL}
	$(Q) ctags -R

gtags: ${SRC_ALL}
	$(Q) gtags -i

clangd: ${SRC_ALL} $(TARGET)
	$(Q) python3 scripts/gen_compile_commands.py

clean:
	$(E) "  CLEAN"
	$(Q) rm -rf $(OBJ) $(TARGET) .*.cmd *.deb *.rpm debbuild rpmbuild
	$(Q) make clean -C common --no-print-directory
	$(Q) make clean -C dtt --no-print-directory
	$(Q) make clean -C dtt-cli --no-print-directory
	$(Q) make clean -C examples --no-print-directory
	$(Q) make clean -C test --no-print-directory

distclean: clean
	$(Q) rm -rf tags GPATH GRTAGS GTAGS compile_commands.json

.PHONY: tags gtags
