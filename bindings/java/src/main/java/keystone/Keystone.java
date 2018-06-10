/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;
import keystone.utilities.Version;

/**
 * The Keystone engine.
 */
public class Keystone {
    /**
     * The native proxy for calling the C library.
     */
    private final KeystoneNative ks;

    /**
     * Initializes a new instance of the class {@link Keystone}.
     */
    public Keystone() {
        this.ks = Native.loadLibrary("keystone", KeystoneNative.class);
    }

    /**
     * Gets the major and minor version numbers.
     *
     * @return The returned value is an instance of the class {@link Version}, containing the major and minor version numbers.
     */
    public Version version() {
        var major = new IntByReference();
        var minor = new IntByReference();

        ks.ks_version(major, minor);

        return new Version(major.getValue(), minor.getValue());
    }
}
