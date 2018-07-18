/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.jna;

import keystone.*;

/**
 * Extends the numeration type mapper in order to register the enumeration used by Keystone.
 */
public class KeystoneTypeMapper extends EnumTypeMapper {
    public KeystoneTypeMapper() {
        addTypeConverter(KeystoneError.class, KeystoneError::fromValue);
        addTypeConverter(KeystoneArchitecture.class, KeystoneArchitecture::fromValue);
        addTypeConverter(KeystoneMode.class, KeystoneMode::fromValue);
        addTypeConverter(KeystoneOptionType.class, KeystoneOptionType::fromValue);
        addTypeConverter(KeystoneOptionValue.KeystoneOptionSyntax.class, KeystoneOptionValue.KeystoneOptionSyntax::fromValue);
    }
}
