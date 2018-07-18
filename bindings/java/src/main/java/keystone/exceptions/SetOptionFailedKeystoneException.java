/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.exceptions;

import keystone.KeystoneError;
import keystone.KeystoneOptionType;

/**
 * An exception that represents an error while setting an option in the Keystone library.
 */
public class SetOptionFailedKeystoneException extends KeystoneException {
    /**
     * The type of the option that generated the exception.
     */
    private final KeystoneOptionType optionType;

    /**
     * The value of the option that generated the exception.
     */
    private final int optionValue;

    public SetOptionFailedKeystoneException(KeystoneError keystoneError, KeystoneOptionType type, int value) {
        super(keystoneError, createErrorMessage(type, value));
        this.optionType = type;
        this.optionValue = value;
    }

    private static String createErrorMessage(KeystoneOptionType type, int value) {
        return "Error while setting the option `" + type +
                "` with the value `" + value + "`";
    }

    /**
     * Gets the type of the option that generated the exception.
     */
    public KeystoneOptionType getOptionType() {
        return optionType;
    }

    /**
     * Gets the value of the option that generated the exception.
     */
    public int getOptionValue() {
        return optionValue;
    }
}
