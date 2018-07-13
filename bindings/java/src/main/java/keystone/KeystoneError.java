/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

import keystone.jna.JnaEnum;

import java.util.HashMap;
import java.util.Map;

/**
 * All type of errors encountered by Keystone API.
 */
public enum KeystoneError implements JnaEnum {

    /**
     * No error: everything was fine.
     */
    Ok(0),

    /**
     * Out-Of-Memory error: ks_open(), ks_emulate().
     */
    Nomem(1),

    /**
     * Unsupported architecture: ks_open().
     */
    Arch(2),

    /**
     * Invalid handle.
     */
    Handle(3),

    /**
     * Invalid/unsupported mode: ks_open().
     */
    Mode(4),

    /**
     * Unsupported version (bindings).
     */
    Version(5),

    /**
     * Unsupported option.
     */
    OptInvalid(6),

    // generic input assembly errors - parser specific

    /**
     * Unknown token in expression.
     */
    AsmExprToken(Base.asm),

    /**
     * Literal value out of range for directive.
     */
    AsmDirectiveValueRange(Base.asm + 1),

    /**
     * Expected identifier in directive.
     */
    AsmDirectiveId(Base.asm + 2),

    /**
     * Unexpected token in directive.
     */
    AsmDirectiveToken(Base.asm + 3),

    /**
     * Expected string in directive.
     */
    AsmDirectiveStr(Base.asm + 4),

    /**
     * Expected comma in directive.
     */
    AsmDirectiveComma(Base.asm + 5),

    /**
     * Expected relocation name in directive.
     */
    AsmDirectiveRelocName(Base.asm + 6),

    /**
     * Unexpected token in .reloc directive.
     */
    AsmDirectiveRelocToken(Base.asm + 7),

    /**
     * Invalid floating point in directive.
     */
    AsmDirectiveFpoint(Base.asm + 8),

    /**
     * Unknown directive.
     */
    AsmDirectiveUnknown(Base.asm + 9),

    /**
     * Invalid equal directive.
     */
    AsmDirectiveEqu(Base.asm + 10),

    /**
     * (Generic) invalid directive.
     */
    AsmDirectiveInvalid(Base.asm + 11),

    /**
     * Invalid variant.
     */
    AsmVariantInvalid(Base.asm + 12),

    /**
     * Brackets expression not supported on this target.
     */
    AsmExprBracket(Base.asm + 13),

    /**
     * Unexpected symbol modifier following '@'.
     */
    AsmSymbolModifier(Base.asm + 14),

    /**
     * Invalid symbol redefinition.
     */
    AsmSymbolRedefined(Base.asm + 15),

    /**
     * Cannot find a symbol.
     */
    AsmSymbolMissing(Base.asm + 16),

    /**
     * Expected ')' in parentheses expression.
     */
    AsmRparen(Base.asm + 17),

    /**
     * Unexpected token at start of statement.
     */
    AsmStatToken(Base.asm + 18),

    /**
     * Unsupported token yet.
     */
    AsmUnsupported(Base.asm + 19),

    /**
     * Unexpected token in macro instantiation.
     */
    AsmMacroToken(Base.asm + 20),

    /**
     * Unbalanced parentheses in macro argument.
     */
    AsmMacroParen(Base.asm + 21),

    /**
     * Expected '=' after formal parameter identifier.
     */
    AsmMacroEqu(Base.asm + 22),

    /**
     * Too many positional arguments.
     */
    AsmMacroArgs(Base.asm + 23),

    /**
     * Macros cannot be nested more than 20 levels deep.
     */
    AsmMacroLevelsExceed(Base.asm + 24),

    /**
     * Invalid macro string.
     */
    AsmMacroStr(Base.asm + 25),

    /**
     * Invalid macro (generic error).
     */
    AsmMacroInvalid(Base.asm + 26),

    /**
     * Unexpected backslash at end of escaped string.
     */
    AsmEscBackslash(Base.asm + 27),

    /**
     * Invalid octal escape sequence  (out of range).
     */
    AsmEscOctal(Base.asm + 28),

    /**
     * Invalid escape sequence (unrecognized character).
     */
    AsmEscSequence(Base.asm + 29),

    /**
     * Broken escape string.
     */
    AsmEscStr(Base.asm + 30),

    /**
     * Invalid token.
     */
    AsmTokenInvalid(Base.asm + 31),

    /**
     * This instruction is unsupported in this mode.
     */
    AsmInsnUnsupported(Base.asm + 32),

    /**
     * Invalid fixup.
     */
    AsmFixupInvalid(Base.asm + 33),

    /**
     * Invalid label.
     */
    AsmLabelInvalid(Base.asm + 34),

    /**
     * Invalid fragment.
     */
    AsmFragmentInvalid(Base.asm + 35),

    // generic input assembly errors - architecture specific

    AsmInvalidOperand(Base.asmArch),
    AsmMissingFeature(Base.asmArch + 1),
    AsmMnemonicFail(Base.asmArch + 2);

    /**
     * Mapping table to determine an enumeration value based on an integer with a complexity of θ(1).
     */
    private static Map<Integer, KeystoneError> intToEnumMapping = new HashMap<>();

    static {
        // Initializes the mapping table.
        for (KeystoneError error : KeystoneError.values()) {
            intToEnumMapping.put(error.value(), error);
        }
    }

    /**
     * Holds the integer value of the enumeration, that corresponds to the value used in the enumeration in C.
     */
    private final int value;

    /**
     * Constructor of the enumeration.
     *
     * @param value The integer value, that corresponds to the value used in the enumeration in C.
     */
    KeystoneError(int value) {

        this.value = value;
    }

    /**
     * Converts an integer value into its corresponding enumeration value.
     * <p>
     * The complexity of the conversion is θ(1).
     *
     * @param value The integer value.
     * @return The return value is a value of the enumeration.
     */
    public static KeystoneError fromValue(Integer value) {
        return intToEnumMapping.get(value);
    }

    /**
     * Retrieves the value of the enumeration, that corresponds to the value used in the enumeration in C.
     *
     * @return The return value is an integer value.
     */
    public int value() {
        return value;
    }

    /**
     * Internal interface referencing the base error codes.
     */
    interface Base {
        int asm = 128;
        int asmArch = 512;
    }
}
