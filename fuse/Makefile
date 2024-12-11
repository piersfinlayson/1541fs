CC = gcc
CPPFLAGS = -D_FORTIFY_SOURCE=2 -D_POSIX_C_SOURCE=200809L
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wformat-truncation \
         -Wformat-overflow -Wshadow -Wcast-align -Wstrict-aliasing \
         -Wcast-qual -Wconversion -Wdouble-promotion -fstack-protector-strong \
         -fPIC -pipe -O2 -g -fdiagnostics-color=always
LDFLAGS = -Wl,-z,relro,-z,now
LIBS = -lopencbm -lfuse3 -lpthread

TARGET = 1541fs-fuse
SRC = cbmargs.c     \
      cbmchannel.c  \
	  cbmdummy.c    \
      cbmfile.c     \
      cbmfuse.c     \
      cbmlog.c      \
      cbmmain.c     \
      cbmsignal.c   \
      cbmstatus.c   \
      cbmthread.c
OBJ = $(addprefix obj/,$(SRC:.c=.o))

# Version info from git
VERSION = $(shell git describe --always --dirty)
CPPFLAGS += -DVERSION=\"$(VERSION)\" -DDEBUG_BUILD

# Dependencies
DEPS = $(OBJ:.o=.d)
CFLAGS += -MMD -MP

$(TARGET): $(OBJ) | obj
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

obj/%.o: %.c | obj
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

obj:
	mkdir -p obj

clean:
	rm -f $(TARGET) $(OBJ) $(DEPS)
	rmdir obj 2>/dev/null || true

-include $(DEPS)

.PHONY: clean