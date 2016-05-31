CFLAGS = -Wall
LIBNAME = keystone
LOADLIBES = -l$(LIBNAME)
PROGS = $(patsubst %.c, %, $(wildcard crash-??-*.c))
all: $(PROGS)
clean:
	$(RM) $(PROGS)
