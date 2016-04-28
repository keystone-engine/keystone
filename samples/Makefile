# Sample code for Keystone Assembler Engine (www.keystone-engine.org).
# By Nguyen Anh Quynh, 2016

.PHONY: all clean

KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm

all:
	${CC} -o sample sample.c ${KEYSTONE_LDFLAGS}

clean:
	rm -rf *.o sample
