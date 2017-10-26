# keystone-rs
Rust bindings for the [keystone](http://www.keystone-engine.org/) engine.

## Sample
```rust
extern crate keystone;
use keystone::*;

fn main() {
    let engine = Keystone::new(Arch::X86, MODE_32)
        .expect("Could not initialize Keystone engine");

    engine.option(OptionType::SYNTAX, OPT_SYNTAX_NASM)
        .expect("Could not set option to nasm syntax");

    let result = engine.asm("mov ah, 0x80".to_string(), 0)
        .expect("Could not assemble");

    println!("ASM result: {}", result);

    if let Err(err) = engine.asm("INVALID".to_string(), 0) {
        println!("Error: {}", err);
    }
}
```

## Testing
```
cargo test
```

## Contributors
- Remco Verhoef (@remco_verhoef)

Special thanks to:
- Sébastien Duquette (@ekse) for his [unicorn-rs](https://github.com/ekse/unicorn-rs) binding
