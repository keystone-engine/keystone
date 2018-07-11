/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

import keystone.exceptions.AssembleFailedKeystoneException;
import keystone.utilities.Version;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedList;

import static org.junit.jupiter.api.Assertions.*;

class KeystoneTest {

    private Keystone keystone;

    @BeforeEach
    void setUp() {
        keystone = new Keystone(KeystoneArchitecture.X86, KeystoneMode.Mode64);
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void assemble_shouldAssembleIncDec() {
        // Arrange
        var assembly = "INC EAX;DEC EAX";
        var expectedMachineCode = new byte[]{(byte) 0xFF, (byte) 0xC0, (byte) 0xFF, (byte) 0xC8};
        var expectedNumberOfStatements = 2;

        // Act
        var encoded = keystone.assemble(assembly);

        // Assert
        assertArrayEquals(expectedMachineCode, encoded.getMachineCode());
        assertEquals(expectedNumberOfStatements, encoded.getNumberOfStatements());
    }

    @Test
    void assemble_withAddress_shouldAssembleDoubleNop() {
        // Arrange
        var assembly = "NOP;NOP";
        var expectedMachineCode = new byte[]{(byte) 0x90, (byte) 0x90};
        var expectedNumberOfStatements = 2;
        var expectedAddress = 0x200;

        // Act
        var encoded = keystone.assemble(assembly, expectedAddress);

        // Assert
        assertArrayEquals(expectedMachineCode, encoded.getMachineCode());
        assertEquals(expectedNumberOfStatements, encoded.getNumberOfStatements());
        assertEquals(expectedAddress, encoded.getAddress());
    }

    @Test
    void assemble_ifAssemblyCodeInvalid_shouldThrowAnException() {
        try {
            keystone.assemble("UNK", 0);
            fail("The assembly instruction is invalid. It should not pass the unit test.");
        } catch (AssembleFailedKeystoneException e) {
            assertEquals(KeystoneError.AsmMnemonicFail, e.getKeystoneError());
        }
    }

    @Test
    void assemble_withCollectionAndAddress_shouldAssembleIncDec() {
        // Arrange
        var assembly = new LinkedList<String>();
        var expectedMachineCode = new byte[]{(byte) 0xFF, (byte) 0xC0, (byte) 0xFF, (byte) 0xC8};
        var expectedNumberOfStatements = 2;

        // Act
        assembly.add("INC EAX");
        assembly.add("DEC EAX");
        var encoded = keystone.assemble(assembly);

        // Assert
        assertArrayEquals(expectedMachineCode, encoded.getMachineCode());
        assertEquals(expectedNumberOfStatements, encoded.getNumberOfStatements());
    }

    @Test
    void version_shouldBeDifferentFromZero() {
        assertEquals(1, keystone.version().compareTo(new Version(0, 0)));
    }

    @Test
    void close_shouldNotThrowAnyException() {
        keystone.close();
    }
}