/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.exceptions;

import keystone.KeystoneError;
import keystone.natives.KeystoneNative;

/**
 * An exception that represents a failure while assembling code.
 */
public class AssembleFailedKeystoneException extends KeystoneException {
    /**
     * The assembly code that generates the error.
     */
    private final String assembly;

    public AssembleFailedKeystoneException(KeystoneNative ksNative, KeystoneError keystoneError, String assembly) {
        super(ksNative, keystoneError, "Error while assembling `" + assembly + "`");

        this.assembly = assembly;
    }

    /**
     * Gets the assembly code that generates the error.
     */
    public String getAssembly() {
        return assembly;
    }
}
