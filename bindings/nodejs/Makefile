# Python binding for Keystone engine. Nguyen Anh Quynh <aquynh@gmail.com>

ifndef BUILDDIR
OBJDIR = ./build
else
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/nodejs
endif

.PHONY: gen_const install clean

gen_const:
	cd .. && python const_generator.py nodejs

install:
	npm install ./

clean:

check:
	node sample.js

