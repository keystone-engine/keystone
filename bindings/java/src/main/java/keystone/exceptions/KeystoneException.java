/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.exceptions;

import keystone.KeystoneError;
import keystone.natives.DirectMappingKeystoneNative;

/**
 * The base class for all the exceptions thrown by the library Keystone.
 */
public abstract class KeystoneException extends RuntimeException {
    /**
     * The error thrown by Keystone.
     */
    private final KeystoneError keystoneError;

    /**
     * Creates a new instance of {@link KeystoneException}.
     *
     * @param keystoneError The error code of Keystone.
     * @param message       A human-readable message of the error.
     */
    KeystoneException(KeystoneError keystoneError, String message) {
        super(message + " : " + DirectMappingKeystoneNative.ks_strerror(keystoneError));

        this.keystoneError = keystoneError;
    }

    /**
     * Gets the error code of Keystone.
     */
    public KeystoneError getKeystoneError() {
        return keystoneError;
    }
}
