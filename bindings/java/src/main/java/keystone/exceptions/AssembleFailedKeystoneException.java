/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.exceptions;

import keystone.KeystoneError;

/**
 * An exception that represents a failure while assembling code.
 */
public class AssembleFailedKeystoneException extends KeystoneException {
    public AssembleFailedKeystoneException(KeystoneError keystoneError, String assembly) {
        super(keystoneError,
                "Keystone library could not assemble (ks_asm) the following assembly code: " + assembly +
                        ", error: " + keystoneError);
    }
}
