# Python binding for Keystone engine. Nguyen Anh Quynh <aquynh@gmail.com>

ifndef BUILDDIR
OBJDIR = ./build
else
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/go
endif

.PHONY: gen_const install clean

gen_const:
	cd .. && python const_generator.py go

install:
	cd keystone && go build

clean:

check:
	cd keystone && go test
