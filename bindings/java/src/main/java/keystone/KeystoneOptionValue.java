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
 * Runtime option values (associated with {@link KeystoneOptionType}).
 */
public class KeystoneOptionValue {

    /**
     * Runtime option values associated with the assembly syntax.
     *
     * @see KeystoneOptionType#Syntax
     */
    public enum KeystoneOptionSyntax implements JnaEnum {
        /**
         * X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
         */
        Intel(1),

        /**
         * X86 ATT asm syntax (KS_OPT_SYNTAX).
         */
        Att(1 << 1),

        /**
         * X86 Nasm syntax (KS_OPT_SYNTAX).
         */
        Nasm(1 << 2),

        /**
         * X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
         */
        Masm(1 << 3),

        /**
         * X86 GNU GAS syntax (KS_OPT_SYNTAX).
         */
        Gas(1 << 4),

        /**
         * All immediates are in hex format (i.e 12 is 0x12).
         */
        Radix16(1 << 5);

        /**
         * Mapping table to determine an enumeration value based on an integer with a complexity of θ(1).
         */
        private static Map<Integer, KeystoneOptionSyntax> intToEnumMapping = new HashMap<>();

        static {
            // Initializes the mapping table.
            for (KeystoneOptionSyntax syntax : KeystoneOptionSyntax.values()) {
                intToEnumMapping.put(syntax.value(), syntax);
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
        KeystoneOptionSyntax(int value) {
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
        public static KeystoneOptionSyntax fromValue(Integer value) {
            return intToEnumMapping.get(value);
        }

        /**
         * Retrieves the value of an element in the enumeration.
         *
         * @return The return value is an integer number, that represents the value in the native library.
         */
        @Override
        public int value() {
            return value;
        }
    }
}