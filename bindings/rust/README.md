# keystone-rs
Rust bindings for the [keystone](http://www.keystone-engine.org/) engine.

## Sample
```rust
extern crate keystone;
use keystone::*;

fn main() {
    let engine = Keystone::new(Arch::X86, Mode::MODE_32)
        .expect("Could not initialize Keystone engine");

    engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)
        .expect("Could not set option to nasm syntax");

    let result = engine.asm("mov ah, 0x80".to_string(), 0)
        .expect("Could not assemble");

    println!("ASM result: {}", result);

    if let Err(err) = engine.asm("INVALID".to_string(), 0) {
        println!("Error: {}", err);
    }
}
```

## Installation
Add a dependency line into `Cargo.toml`.

```
[dependencies]
keystone = "0.9.2"
```

This package attempts to build keystone. That requires cmake and c/c++ compiler.

If you want to use keystone already installed in the system, specify `use_system_keystone` feature on `Cargo.toml`.

```
[dependencies.keystone]
version = "0.9.2"
default-features = false
features = ["use_system_keystone"]
```

## Testing
```
cargo test
```

## Contributors
- Remco Verhoef (@remco_verhoef)
- Tasuku SUENAGA a.k.a. gunyarakun (@tasukuchan)

Special thanks to:
- Sébastien Duquette (@ekse) for his [unicorn-rs](https://github.com/ekse/unicorn-rs) binding
