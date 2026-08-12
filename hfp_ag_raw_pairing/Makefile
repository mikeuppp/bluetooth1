CC ?= gcc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -D_FORTIFY_SOURCE=2
LDFLAGS ?=

TARGET := hfp_pair
OBJS := main.o pairing.o sdp.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

main.o: main.c pairing.h sdp.h bt_defs.h
pairing.o: pairing.c pairing.h sdp.h bt_defs.h
sdp.o: sdp.c sdp.h bt_defs.h

clean:
	rm -f $(TARGET) $(OBJS)
