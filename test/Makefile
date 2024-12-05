CC = gcc
CPPFLAGS = -D_FORTIFY_SOURCE=2 -D_POSIX_C_SOURCE=200809L
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wformat-truncation \
         -Wformat-overflow -Wshadow -Wcast-align -Wstrict-aliasing \
         -Wcast-qual -Wconversion -Wdouble-promotion -fstack-protector-strong \
         -fPIC -pipe -O2 -g
LDFLAGS = -Wl,-z,relro,-z,now
LIBS = -lopencbm

TARGET = 1541fs-test
SRC = test.c
OBJ = $(SRC:.c=.o)

# Version info from git
VERSION = $(shell git describe --always --dirty)
CPPFLAGS += -DVERSION=\"$(VERSION)\"

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