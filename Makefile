ROOT = .
SRC_DIR = ./src/
BIN_DIR = ./bin/


GETSC_NAME = get_sc
GETSC_SRCS = $(GETSC_NAME).c
GETSC_SRC = $(addprefix $(SRC_DIR), $(GETSC_SRCS))
GETSC_OBJS = $(GETSC_SRC:.c=.o)
GETSC = $(addprefix $(BIN_DIR), $(GETSC_NAME))

RELF_NAME = readelf
RELF_SRCS = $(RELF_NAME).c
RELF_SRC = $(addprefix $(SRC_DIR), $(RELF_SRCS))
RELF_OBJS = $(RELF_SRC:.c=.o)
RELF = $(addprefix $(BIN_DIR), $(RELF_NAME))

CC=gcc

CFLAGS=-std=gnu99
LDFLAGS=-lelf


# Be silent per default, but 'make V=1' will show all compiler calls.
ifneq ($(V),1)
Q := @
# Do not print "Entering directory ...".
MAKEFLAGS += --no-print-directory
endif


getsc: $(GETSC_OBJS)
	$(CC) -o $(GETSC) $(GETSC_OBJS) $(CFLAGS) $(LDFLAGS)

readelf: $(RELF_OBJS)
	$(CC) -o $(RELF) $(RELF_OBJS) $(CFLAGS) $(LDFLAGS)

all:	getsc readelf

clean:
	rm -f src/*.o $(GETSC) $(RELF)
