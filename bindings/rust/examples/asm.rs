extern crate keystone;
use keystone::{Keystone, Arch, Mode, OptionType, OptionValue};

fn main() {
    let engine = Keystone::new(Arch::X86, Mode::Mode32)
        .expect("Could not initialize Keystone engine");

    engine.option(OptionType::Syntax, OptionValue::SyntaxNASM)
        .expect("Could not set option to nasm syntax");

    let result = engine.asm("mov ah, 0x80".to_string(), 0)
        .expect("Could not assemble");

    let _ = result;
}

