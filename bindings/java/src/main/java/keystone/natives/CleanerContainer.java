/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.natives;

import java.lang.ref.Cleaner;

/**
 * An abstract class that automatically runs the action passed by argument in the constructor once
 * phantom reachable, thanks to {@link Cleaner}.
 *
 * @see Cleaner
 * @see <a href="https://www.linkedin.com/pulse/java-9-cleaner-illustration-good-encapsulation-pawel-wlodarski/">Java 9 Cleaner as an illustration of good encapsulation</a>
 */
public abstract class CleanerContainer implements AutoCloseable {
    /**
     * Creates a single instance of the cleaner for all the native resources.
     */
    private static final Cleaner cleaner = Cleaner.create();

    /**
     * The instance of {@link java.lang.ref.Cleaner.Cleanable} that refers to the native resource.
     */
    private final Cleaner.Cleanable cleanable;

    /**
     * Registers a cleaning action to run when the object becomes phantom reachable.
     *
     * @param action a {@code Runnable} to invoke when the object becomes phantom reachable.
     */
    CleanerContainer(Runnable action) {
        cleanable = cleaner.register(this, action);
    }

    /**
     * Closes this resource, relinquishing any underlying resources.
     * This method is invoked automatically on objects managed by the
     * {@code try}-with-resources statement.
     */
    @Override
    public void close() {
        cleanable.clean();
    }
}
