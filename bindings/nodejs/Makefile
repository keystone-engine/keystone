# NodeJS binding for Keystone engine. Ingmar Steen 

ifndef BUILDDIR
OBJDIR = ./build
else
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/nodejs
endif

.PHONY: gen_const install clean check

gen_const:
	cd .. && python const_generator.py nodejs

install:
	npm install ./

clean:

check:
	node sample.js

