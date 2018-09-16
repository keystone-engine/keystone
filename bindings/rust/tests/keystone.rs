extern crate keystone;

use keystone::{Arch, Error, Keystone, Mode, OptionType, OptionValue};

#[test]
fn version() {
    let (major, minor) = keystone::version();
    assert_eq!((major, minor), keystone::bindings_version());
}

#[test]
fn arch_supported() {
    assert_eq!(keystone::arch_supported(Arch::ARM), true);
    assert_eq!(keystone::arch_supported(Arch::X86), true);
}

#[test]
fn asm() {
    let asm = String::from("mov ah, 0x80\n nop\n mov al, 0x81\n");

    let engine = Keystone::new(Arch::X86, Mode::LITTLE_ENDIAN | Mode::MODE_32)
        .expect("Could not initialize Keystone engine");

    engine
        .option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)
        .expect("Could not set option to nasm syntax");

    let result = engine.asm(asm, 0).expect("Could not assemble");

    print!("{0:?}", result.bytes);
    assert_eq!(result.bytes, [0xb4, 0x80, 0x90, 0xb0, 0x81]);
}

#[test]
fn invalid_asm() {
    let asm = String::from("invalid asm");

    let engine =
        Keystone::new(Arch::X86, Mode::MODE_32).expect("Could not initialize Keystone engine");

    let result = engine.asm(asm, 0);
    let err = result.unwrap_err();

    assert_eq!(err, Error::ASM_MNEMONICFAIL);
    assert_eq!(err.msg(), "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)");
    assert_eq!(
        format!("{}", err),
        "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
    );
}
