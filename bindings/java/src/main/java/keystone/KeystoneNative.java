/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

import com.sun.jna.Library;
import com.sun.jna.ptr.IntByReference;

/**
 * Contract used by JNA to interoperate with the native C code of the library.
 */
public interface KeystoneNative extends Library {
    /**
     * Returns combined API version & major and minor version numbers.
     *
     * @param major The major number of API version.
     * @param minor The minor number of API version.
     * @return An hexadecimal number as (major << 8 | minor), which encodes both major & minor versions.
     */
    int ks_version(IntByReference major, IntByReference minor);
}