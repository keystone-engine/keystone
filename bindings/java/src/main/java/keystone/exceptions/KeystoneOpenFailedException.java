/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.exceptions;

import keystone.KeystoneError;

/**
 * An exception that represents a failure to open the library Keystone.
 */
public class KeystoneOpenFailedException extends KeystoneException {
    public KeystoneOpenFailedException(KeystoneError error) {
        super(error, "Keystone library could not be opened (ks_open), error: " + error.name());
    }
}
