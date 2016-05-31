# Rust binding for Keystone engine. Remco Verhoef <remco@honeytrap.io>

ifndef BUILDDIR
OBJDIR = ./build
else
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/rust
endif

.PHONY: gen_const install clean check

gen_const:
	cd .. && python const_generator.py rust
	cargo fmt

install:
	cargo build

clean:
	rm -rf target/

check:
	cargo test

