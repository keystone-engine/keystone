/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

import com.sun.jna.ptr.LongByReference;
import keystone.exceptions.AssembleFailedKeystoneException;
import keystone.exceptions.OpenFailedKeystoneException;
import keystone.exceptions.SetOptionFailedKeystoneException;
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
    void ctor_ifInvalidArguments_shouldThrowAnException() {
        try {
            new Keystone(KeystoneArchitecture.Ppc, KeystoneMode.SparcV9);
            fail("An exception must be thrown upon invalid arguments are used.");
        } catch (OpenFailedKeystoneException e) {
            assertEquals(KeystoneError.Mode, e.getKeystoneError());
        }
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
        // Arrange
        var assembly = "UNK";

        // Act and Assert
        try {
            keystone.assemble(assembly, 0);
            fail("The assembly instruction is invalid. It should not pass the unit test.");
        } catch (AssembleFailedKeystoneException e) {
            assertEquals(KeystoneError.AsmMnemonicFail, e.getKeystoneError());
            assertEquals(assembly, e.getAssembly());
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
    void assemble_withSymbolWithoutResolver_shouldFail() {
        // Arrange
        var assembly = "MOV EAX, TEST";

        // Act and Assert
        try {
            keystone.assemble(assembly);
            fail("The assembly instruction is composed of an undefined symbol. It should not pass the unit test");
        } catch (AssembleFailedKeystoneException e) {
            assertEquals(KeystoneError.AsmSymbolMissing, e.getKeystoneError());
        }
    }

    @Test
    void setAssemblySyntax_withAttSyntax_shouldBeEqualToX86Syntax() {
        // Act
        var x86Result = keystone.assemble("INC ECX; DEC EDX");
        keystone.setAssemblySyntax(KeystoneOptionValue.KeystoneOptionSyntax.Att);
        var attResult = keystone.assemble("INC %ecx; DEC %edx");

        // Assert
        assertArrayEquals(x86Result.getMachineCode(), attResult.getMachineCode());
    }

    @Test
    void setOption_ifInvalidArguments_shouldTrowAnException() {
        // Arrange
        var expectedType = KeystoneOptionType.Syntax;
        var invalidValue = -1;

        // Act and Assert
        try {
            keystone.setOption(expectedType, invalidValue);
        } catch (SetOptionFailedKeystoneException e) {
            assertEquals(KeystoneError.OptInvalid, e.getKeystoneError());
            assertEquals(expectedType, e.getOptionType());
            assertEquals(invalidValue, e.getOptionValue());
        }
    }

    @Test
    void setSymbolResolver_assembleCustomSymbol_shouldProduceValidAssemblyCode() {
        // Arrange
        var expectedSymbol = "TEST";
        var expectedValue = (byte) 0x66;
        var movOpcode = (byte) 0xB8;
        var assembly = "MOV EAX, " + expectedSymbol;
        var symbolResolver = new SymbolResolverCallback() {
            @Override
            public boolean onResolve(String symbol, LongByReference value) {
                assertEquals(expectedSymbol, symbol);

                value.setValue(expectedValue);
                return true;
            }
        };

        // Act
        keystone.setSymbolResolver(symbolResolver);
        var assemblyCode = keystone.assemble(assembly);

        // Assert
        assertEquals(1, assemblyCode.getNumberOfStatements());
        assertEquals(movOpcode, assemblyCode.getMachineCode()[0]);
        assertEquals(expectedValue, assemblyCode.getMachineCode()[1]);
    }

    @Test
    void unsetSymbolResolver_assembleCustomSymbol_shouldfailBecauseTheCallbackHasBeenUnset() {
        // Arrange
        var expectedSymbol = "TEST";
        var expectedValue = (byte) 0x66;
        var assembly = "MOV EAX, " + expectedSymbol;
        var symbolResolver = new SymbolResolverCallback() {
            @Override
            public boolean onResolve(String symbol, LongByReference value) {
                assertEquals(expectedSymbol, symbol);

                value.setValue(expectedValue);
                return true;
            }
        };

        // Act and Assert
        keystone.setSymbolResolver(symbolResolver);
        keystone.unsetSymbolResolver();

        try {
            keystone.assemble(assembly);
            fail("The assembly instruction is composed of an undefined symbol and no resolver should be available.");
        } catch (AssembleFailedKeystoneException e) {
            assertEquals(KeystoneError.AsmSymbolMissing, e.getKeystoneError());
        }
    }

    @Test
    void isArchitectureSupported_shouldSupportX86Everywhere() {
        assertTrue(Keystone.isArchitectureSupported(KeystoneArchitecture.X86));
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