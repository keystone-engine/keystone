/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.natives;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import keystone.KeystoneArchitecture;
import keystone.KeystoneError;
import keystone.KeystoneMode;

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

    /**
     * Close KS instance: MUST do to release the handle when it is not used anymore.
     * NOTE: this must be called only when there is no longer usage of Keystone.
     * The reason is this API releases some cached memory, thus access to any
     * Keystone API after ks_close() might crash your application.
     * After this, @engine is invalid, and no longer usable.
     *
     * @param engine pointer to a handle returned by ks_open().
     * @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum for detailed error).
     */
    KeystoneError ks_close(Pointer engine);

    /**
     * Create new instance of Keystone engine.
     *
     * @param architecture architecture type (KS_ARCH_*).
     * @param mode hardware mode. This is combined of KS_MODE_*.
     * @param engine pointer to ks_engine, which will be updated at return time.
     * @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum for detailed error).
     */
    // ks_err ks_open(ks_arch arch, int mode, ks_engine **ks);
    KeystoneError ks_open(KeystoneArchitecture architecture, KeystoneMode mode, PointerByReference engine);
}