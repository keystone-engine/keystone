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

public enum KeystoneOptionType implements JnaEnum {
    /**
     * Choose syntax for input assembly.
     */
    Syntax(1),

    /**
     * Set symbol resolver callback.
     */
    SymbolResolver(2);

    /**
     * Mapping table to determine an enumeration value based on an integer with a complexity of θ(1).
     */
    private static Map<Integer, KeystoneOptionType> intToEnumMapping = new HashMap<>();

    static {
        // Initializes the mapping table.
        for (KeystoneOptionType type : KeystoneOptionType.values()) {
            intToEnumMapping.put(type.value(), type);
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
    KeystoneOptionType(int value) {
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
    public static KeystoneOptionType fromValue(Integer value) {
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
}
