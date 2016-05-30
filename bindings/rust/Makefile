# Python binding for Keystone engine. Nguyen Anh Quynh <aquynh@gmail.com>

ifndef BUILDDIR
OBJDIR = ./build
else
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/rust
endif

.PHONY: gen_const install install3 clean

gen_const:
	cd .. && python const_generator.py rust

install:
	cargo build

clean:
	rm -rf target/

check:
	cargo test

