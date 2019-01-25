# Rust binding for Keystone engine. Remco Verhoef <remco@honeytrap.io>

.PHONY: gen_const build package clean check

build:
	cargo build -vv

package:
	cd keystone-sys && cargo package -vv
	cargo package -vv

clean:
	cargo clean

check:
# 	Make sure to only use one test thread as keystone isn't thread-safe
	cargo test -- --test-threads=1

gen_const:
	cd .. && python2 const_generator.py rust
	cargo fmt
