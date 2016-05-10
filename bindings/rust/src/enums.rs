pub use keystone_const::*;

#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Arch {
    ARM = KS_ARCH_ARM,
    ARM64 =KS_ARCH_ARM64,
    MIPS = KS_ARCH_MIPS,
    X86 = KS_ARCH_X86,
    PPC = KS_ARCH_PPC,
    SPARC = KS_ARCH_SPARC,
    SYSTEMZ = KS_ARCH_SYSTEMZ,
    HEXAGON = KS_ARCH_HEXAGON,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Mode {
    LittleEndian = KS_MODE_LITTLE_ENDIAN,
    BigEndian = KS_MODE_BIG_ENDIAN,
    /*
    ARM = KS_MODE_ARM,
    THUMB = KS_MODE_THUMB,
    V8 = KS_MODE_V8,
    MICRO = KS_MODE_MICRO,
    MIPS3 = KS_MODE_MIPS3,
    MIPS32R6 = KS_MODE_MIPS32R6,
    MIPS32 = KS_MODE_MIPS32,
    MIPS64 = KS_MODE_MIPS64,
    SIZE_16= KS_MODE_16,
    */
    Mode32 = KS_MODE_32,
    /*
    SIZE_64 = KS_MODE_64,
    PPC32 = KS_MODE_PPC32,
    PPC64 = KS_MODE_PPC64,
    QPX = KS_MODE_QPX,
    SPARC32 = KS_MODE_SPARC32,
    SPARC64 = KS_MODE_SPARC64,
    V9 = KS_MODE_V9,
    */
}

#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    Ok = KS_ERR_OK,
    // ASM = KS_ERR_ASM,
    // ASM_ARCH = KS_ERR_ASM_ARCH,
    NoMem = KS_ERR_NOMEM,
    Arch = KS_ERR_ARCH,
    Handle = KS_ERR_HANDLE,
    Mode = KS_ERR_MODE,
    Version = KS_ERR_VERSION,
    OptionInvalid = KS_ERR_OPT_INVALID,
    AsmExprToken = KS_ERR_ASM_EXPR_TOKEN,
    AsmDirectiveValueRange = KS_ERR_ASM_DIRECTIVE_VALUE_RANGE,
    AsmDirectiveToken = KS_ERR_ASM_DIRECTIVE_ID,
    DirectiveToken = KS_ERR_ASM_DIRECTIVE_TOKEN,
    DirectiveStr =  KS_ERR_ASM_DIRECTIVE_STR,
    DirectiveComma =  KS_ERR_ASM_DIRECTIVE_COMMA,
    DirectiveRelocName =  KS_ERR_ASM_DIRECTIVE_RELOC_NAME,
    DirectiveRelocToken =  KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN,
    DirectiveFPoint =  KS_ERR_ASM_DIRECTIVE_FPOINT,
    VariantInvalid =  KS_ERR_ASM_VARIANT_INVALID,
    ExprBracket =  KS_ERR_ASM_EXPR_BRACKET,
    SymbolModifier =  KS_ERR_ASM_SYMBOL_MODIFIER,
    RParen =  KS_ERR_ASM_RPAREN,
    StatToken =  KS_ERR_ASM_STAT_TOKEN,
    AsmUnsupported = KS_ERR_ASM_UNSUPPORTED,
    AsmMacroToken = KS_ERR_ASM_MACRO_TOKEN,
    AsmMacroParen = KS_ERR_ASM_MACRO_PAREN,
    AsmMacroEQU = KS_ERR_ASM_MACRO_EQU,
    AsmMacroArgs = KS_ERR_ASM_MACRO_ARGS,
    AsmMacroLevelsExceed = KS_ERR_ASM_MACRO_LEVELS_EXCEED,
    AsmEscBackslash = KS_ERR_ASM_ESC_BACKSLASH,
    AsmEscOctal = KS_ERR_ASM_ESC_OCTAL,
    AsmEscSequence =  KS_ERR_ASM_ESC_SEQUENCE,
    AsmInvalidOperand = KS_ERR_ASM_INVALIDOPERAND,
    AsmMissingFeature = KS_ERR_ASM_MISSINGFEATURE,
    AsmMNemonicFail = KS_ERR_ASM_MNEMONICFAIL,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OptionType {
    Syntax = KS_OPT_SYNTAX,
    SYNTAX2 = KS_OPT_SYNTAX_NASM,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OptionValue {
    SyntaxIntel = KS_OPT_SYNTAX_INTEL,
    SyntaxATT = KS_OPT_SYNTAX_ATT,
    SyntaxNASM = KS_OPT_SYNTAX_NASM,
    SyntaxMASM = KS_OPT_SYNTAX_MASM,
    SyntaxGAS = KS_OPT_SYNTAX_GAS,
}


