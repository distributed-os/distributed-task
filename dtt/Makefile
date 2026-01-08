CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar

ifeq ($(strip $(V)),)
	E := @echo
	Q := @
else
	E = @\#
	Q =
endif

CFLAGS := -std=gnu99 -Wall -Wextra -I../common/include -fvisibility=hidden
LDFLAGS :=

ifeq ($(strip $(DEBUG)),)
	CFLAGS += -O2
	LDFLAGS += -s  # strip
else
	CFLAGS += -O0 -g -DDEBUG
endif

SRC += ../common/is.c
SRC += ../common/md5.c
SRC += ../common/crc.c
SRC += ../common/helper.c
SRC += ../common/util.c
SRC += ../common/log.c
SRC += discovery.c
SRC += client.c
SRC += dtt.c

OBJ := $(SRC:.c=.o)

SHARED_LIB := lib/libdtt.so
STATIC_LIB := lib/libdtt.a

all: $(SHARED_LIB) $(STATIC_LIB)

$(SHARED_LIB): $(OBJ)
	$(Q) echo "  CC      " $@
	$(Q) $(CC) -shared -o $@ $^ $(LDFLAGS)

$(STATIC_LIB): $(OBJ)
	$(Q) echo "  AR      " $@
	$(Q) $(AR) -rc -o $@ $^

%.o: %.c
	$(Q) echo "  CC      " $@
	$(Q) $(CC) $(CFLAGS) -fPIC -c $< -o $@
	$(Q) echo "savedcmd_$@ := $(CC) $(CFLAGS) -c -o $@ $<" > .$(@F).cmd

clean:
	$(Q) rm -f $(SHARED_LIB) $(STATIC_LIB) $(OBJ) .*.cmd
