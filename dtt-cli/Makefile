TARGET := dtt

ifeq ($(strip $(V)),)
	E := @echo
	Q := @
else
	E = @\#
	Q =
endif

E := @echo
CC := $(CROSS_COMPILE)gcc

CFLAGS := -std=gnu99 -Wall -Wextra \
	-Iinclude \
	-I../dtt/include \
	-I../common/include

LDFLAGS := -lpthread -lrt \
   -L../dtt/lib -l:libdtt.a \
   -L../common -l:libcommon.a

ifeq ($(strip $(DEBUG)),)
   CFLAGS += -O2
   LDFLAGS += -s  # strip
else
   CFLAGS += -O0 -g -DDEBUG
endif

all: ${TARGET}

SRC_ALL := $(shell find . -name "*.c" -o -name "*.h")

SRC += dtt-cli.c \
	   executor.c  inventory.c  output.c \
	   module-command.c  module-copy.c  module-ping.c

OBJ := $(SRC:.c=.o)

$(TARGET): $(OBJ)
	$(Q) echo "  LD      " $@
	$(Q) $(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(Q) echo "  CC      " $@
	$(Q) $(CC) $(CFLAGS) -c -o $@ $<
	$(Q) echo "savedcmd_$@ := $(CC) $(CFLAGS) -c -o $@ $<" > .$(@F).cmd

gtags: ${SRC_ALL}
	$(Q) gtags -i

clean:
	$(Q) rm -rf $(OBJ) $(TARGET) .*.cmd
	$(Q) rm -rf tags GPATH GRTAGS GTAGS

.PHONY: gtags
