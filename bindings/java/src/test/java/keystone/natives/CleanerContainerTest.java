/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.natives;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CleanerContainerTest {
    @Test
    void dtor_WhenGarbageCollected_ShouldTriggerThePhantomReachableAction() throws InterruptedException {
        // Arrange
        var atomicBoolean = new AtomicBoolean(false);
        new MockCleanerContainer(atomicBoolean);

        // Act
        System.gc();
        Thread.sleep(1);

        // Assert
        assertTrue(atomicBoolean.get());
    }
}

class MockCleanerContainer extends CleanerContainer {

    MockCleanerContainer(AtomicBoolean atomicBoolean) {
        super(new MockState(atomicBoolean));
    }

    static class MockState implements Runnable {

        private final AtomicBoolean atomicBoolean;

        MockState(AtomicBoolean atomicBoolean) {

            this.atomicBoolean = atomicBoolean;
        }

        @Override
        public void run() {
            atomicBoolean.set(true);
        }
    }
}