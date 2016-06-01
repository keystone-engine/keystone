CFLAGS = -Wall
LDLIBS = -l$(LIBNAME)
LIBNAME = keystone
PROGS = $(patsubst %.c, %, $(wildcard crash-??-*.c))
all: $(PROGS)
clean:
	$(RM) $(PROGS)
