CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar

ifeq ($(strip $(V)),)
	E := @echo
	Q := @
else
	E = @\#
	Q =
endif

CFLAGS := -std=gnu99 -Wall -Wextra -I./include
LDFLAGS :=

ifeq ($(strip $(DEBUG)),)
	CFLAGS += -O2
	LDFLAGS += -s  # strip
else
	CFLAGS += -O0 -g -DDEBUG
endif

SRC += is.c
SRC += md5.c
SRC += crc.c
SRC += helper.c
SRC += util.c
SRC += log.c

OBJ := $(SRC:.c=.o)

STATIC_LIB := libcommon.a

all: $(STATIC_LIB)

$(STATIC_LIB): $(OBJ)
	$(Q) echo "  AR      " $@
	$(Q) $(AR) -rc -o $@ $^

%.o: %.c
	$(Q) echo "  CC      " $@
	$(Q) $(CC) $(CFLAGS) -fPIC -c $< -o $@

clean:
	$(Q) rm -f $(STATIC_LIB) $(OBJ)
