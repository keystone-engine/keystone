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
 * The supported architectures of Keystone.
 */
public enum KeystoneArchitecture implements JnaEnum {
    /**
     * ARM architecture (including Thumb, Thumb-2).
     */
    Arm(1),

    /**
     * ARM-64, also called AArch64.
     */
    Arm64(2),

    /**
     * Mips architecture.
     */
    Mips(3),

    /**
     * X86 architecture (including x86 & x86-64).
     */
    X86(4),

    /**
     * PowerPC architecture (currently unsupported).
     */
    Ppc(5),

    /**
     * Sparc architecture.
     */
    Sparc(6),

    /**
     * SystemZ architecture (S390X).
     */
    SystemZ(7),

    /**
     * Hexagon architecture
     */
    Hexagon(8),

    /**
     * Ethereum Virtual Machine architecture.
     */
    Evm(9),

    Max(10);

    /**
     * Mapping table to determine an enumeration value based on an integer with a complexity of θ(1).
     */
    private static Map<Integer, KeystoneArchitecture> intToEnumMapping = new HashMap<>();

    static {
        // Initializes the mapping table.
        for (KeystoneArchitecture architecture : KeystoneArchitecture.values()) {
            intToEnumMapping.put(architecture.value(), architecture);
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
    KeystoneArchitecture(int value) {
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
    public static KeystoneArchitecture fromValue(Integer value) {
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
