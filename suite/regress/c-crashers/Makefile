LIBNAME = keystone
CFLAGS = -Wall -l$(LIBNAME)
PROGS = $(patsubst %.c, %, $(wildcard crash-??-*.c))
all: $(PROGS)
clean:
	$(RM) $(PROGS)
