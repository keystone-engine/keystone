/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.natives;

import com.sun.jna.Pointer;

/**
 * The cleaner that automatically close the {@code Pointer} of Keystone once the managed object is phantom reachable.
 */
public class KeystoneCleanerContainer extends CleanerContainer {

    /**
     * Registers an object and a cleaning action to run when the object becomes phantom reachable.
     */
    public KeystoneCleanerContainer(Pointer pointerToEngine) {
        super(new KeystoneState(pointerToEngine));
    }

    /**
     * The internal state that contains the logic to free the native resource.
     */
    static class KeystoneState implements Runnable {

        /**
         * A pointer to the native resource.
         */
        private final Pointer pointerToEngine;

        /**
         * Create a new instance of {@link KeystoneState}.
         *
         * @param pointerToEngine The pointer to the Keystone native resource.
         */
        KeystoneState(Pointer pointerToEngine) {

            this.pointerToEngine = pointerToEngine;
        }

        /**
         * Calls the logic to collect the native resource.
         */
        @Override
        public void run() {
            DirectMappingKeystoneNative.ks_close(pointerToEngine);
        }
    }
}
