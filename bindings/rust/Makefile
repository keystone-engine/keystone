# Rust binding for Keystone engine. Remco Verhoef <remco@honeytrap.io>

.PHONY: gen_const build package clean check

build: keystone-sys/keystone
	cargo build -vv

package: keystone-sys/keystone
	cd keystone-sys && cargo package -vv
	cargo package -vv

# For packaging we need to embed the keystone source in the crate
keystone-sys/keystone:
	rsync -a ../.. keystone-sys/keystone --exclude bindings --filter ":- ../../.gitignore"

clean:
	rm -rf keystone-sys/keystone/
	cargo clean

check:
# 	Make sure to only use one test thread as keystone isn't thread-safe
	cargo test -- --test-threads=1

gen_const:
	cd .. && python2 const_generator.py rust
	cargo fmt
