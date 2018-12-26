# Rust binding for Keystone engine. Remco Verhoef <remco@honeytrap.io>

.PHONY: gen_const build package clean check

build: keystone-sys/keystone
	cargo build -vv

package: keystone-sys/keystone
	cd keystone-sys && cargo package -vv
	cargo package -vv

keystone-sys/keystone:
	rsync -a ../.. keystone-sys/keystone --exclude bindings --filter ":- ../../.gitignore"

clean:
	rm -rf target/ keystone-sys/target/ keystone-sys/keystone/

check:
	cargo test

gen_const:
	cd .. && python const_generator.py rust
	cargo fmt
