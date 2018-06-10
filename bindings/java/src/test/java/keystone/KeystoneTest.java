/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

import keystone.utilities.Version;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeystoneTest {

    private Keystone keystone;

    @BeforeEach
    void setUp() {
        keystone = new Keystone();
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void version_shouldBeDifferentFromZero() {
        assertEquals(1, keystone.version().compareTo(new Version(0, 0)));
    }
}