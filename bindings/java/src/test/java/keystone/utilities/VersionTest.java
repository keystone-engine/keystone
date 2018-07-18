/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.utilities;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VersionTest {

    private final int major = 3;
    private final int minor = 1;

    @Test
    void major_shouldReturnTheValueSpecifiedInTheConstructor() {
        // Arrange
        var v = new Version(major, minor);

        // Act
        var m = v.major();

        // Assert
        assertEquals(major, m);
    }

    @Test
    void minor_shouldReturnTheValueSpecifiedInTheConstructor() {
        // Arrange
        var v = new Version(major, minor);

        // Act
        var m = v.minor();

        // Assert
        assertEquals(minor, m);
    }

    @Test
    void compareTo_ifMajorIsNotEqual_shouldReturnDifferent() {
        // Arrange
        var v1 = new Version(major, minor);
        var v2 = new Version(major + 1, minor);

        // Act
        var lower = v1.compareTo(v2);
        var higher = v2.compareTo(v1);

        // Assert
        assertEquals(-1, lower);
        assertEquals(1, higher);
    }

    @Test
    void compareTo_ifMinorIsNotEqual_shouldReturnDifferent() {
        // Arrange
        var v1 = new Version(major, minor + 1);
        var v2 = new Version(major, minor);

        // Act
        var lower = v2.compareTo(v1);
        var higher = v1.compareTo(v2);

        // Assert
        assertEquals(-1, lower);
        assertEquals(1, higher);
    }
}