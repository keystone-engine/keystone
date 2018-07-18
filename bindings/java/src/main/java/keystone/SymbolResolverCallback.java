/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

import com.sun.jna.Callback;
import com.sun.jna.ptr.LongByReference;

/**
 * An interface that represents a callback to provide a value for a missing symbol.
 */
public interface SymbolResolverCallback extends Callback {
    /**
     * A callback triggered when a unrecognized symbol is found.
     *
     * @param symbol The symbol to resolve.
     * @param value  The value to modify if the symbol is resolved.
     * @return The return value must be {@code true} if the symbol can be resolved; otherwise {@code false}.
     */
    boolean onResolve(String symbol, LongByReference value);
}
