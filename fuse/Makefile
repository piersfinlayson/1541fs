CC = gcc
CPPFLAGS = -D_FORTIFY_SOURCE=2 -D_POSIX_C_SOURCE=200809L
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wformat-truncation \
         -Wformat-overflow -Wshadow -Wcast-align -Wstrict-aliasing \
         -Wcast-qual -Wconversion -Wdouble-promotion -fstack-protector-strong \
         -fPIC -pipe -O2 -g -fdiagnostics-color=always
LDFLAGS = -Wl,-z,relro,-z,now
LIBS = -lopencbm -lfuse3 -lpthread

TARGET = 1541fs-fuse
SRC = fuse.c
OBJ = $(SRC:.c=.o)

# Version info from git
VERSION = $(shell git describe --always --dirty)
CPPFLAGS += -DVERSION=\"$(VERSION)\" -DDEBUG_BUILD

# Dependencies
DEPS = $(OBJ:.o=.d)
CFLAGS += -MMD -MP

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJ) $(DEPS)

-include $(DEPS)

.PHONY: clean