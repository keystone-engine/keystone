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
 * The supported mode type by Keystone.
 */
public enum KeystoneMode implements JnaEnum {
    /**
     * Little-endian mode (default mode).
     */
    LittleEndian(0),

    /**
     * Big-endian mode.
     */
    BigEndian(1 << 30),

    // arm / arm64

    /**
     * ARM mode.
     */
    Arm(1),

    /**
     * THUMB mode (including Thumb-2).
     */
    ArmThumb(1 << 4),

    /**
     * ARMv8 A32 encodings for ARM.
     */
    ArmV8(1 << 6),

    // mips

    /**
     * MicroMips mode.
     */
    MipsMicro(1 << 4),

    /**
     * Mips III ISA.
     */
    Mips3(1 << 5),

    /**
     * Mips32r6 ISA.
     */
    Mips32r6(1 << 6),

    /**
     * Mips32 ISA.
     */
    Mips32(1 << 2),

    /**
     * Mips64 ISA.
     */
    Mips64(1 << 3),

    // x86 / x64

    /**
     * 16-bit mode.
     */
    Mode16(1 << 1),

    /**
     * 32-bit mode.
     */
    Mode32(1 << 2),

    /**
     * 64-bit mode.
     */
    Mode64(1 << 3),

    // ppc

    /**
     * 32-bit mode.
     */
    Ppc32(1 << 2),

    /**
     * 64-bit mode.
     */
    Ppc64(1 << 3),

    /**
     * Quad Processing eXtensions mode.
     */
    PpcQpx(1 << 4),

    // sparc

    /**
     * 32-bit mode.
     */
    Sparc32(1 << 2),

    /**
     * 64-bit mode.
     */
    Sparc64(1 << 3),

    /**
     * SparcV9 mode.
     */
    SparcV9(1 << 4);

    /**
     * Mapping table to determine an enumeration value based on an integer with a complexity of θ(1).
     */
    private static Map<Integer, KeystoneMode> intToEnumMapping = new HashMap<>();

    static {
        // Initializes the mapping table.
        for (KeystoneMode mode : KeystoneMode.values()) {
            intToEnumMapping.put(mode.value(), mode);
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
    KeystoneMode(int value) {
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
    public static KeystoneMode fromValue(Integer value) {
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
