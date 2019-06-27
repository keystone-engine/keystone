/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.jna;

/**
 * A contract that represents an JNA enumeration.
 */
public interface JnaEnum {
    /**
     * Retrieves the value of an element in the enumeration.
     *
     * @return The return value is an integer number, that represents the value in the native library.
     */
    int value();
}
