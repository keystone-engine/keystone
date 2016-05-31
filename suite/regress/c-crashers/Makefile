CFLAGS = -Wall -Werror -std=c99 -pedantic
LDLIBS = -l$(LIBNAME)
LIBNAME = keystone
PROGS = $(patsubst %.c, %, $(wildcard crash-??-*.c))
all: $(PROGS)
clean:
	$(RM) $(PROGS)
