/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone;

public class KeystoneEncoded {
    private final byte[] machineCode;
    private final int address;
    private final int numberOfStatements;

    public KeystoneEncoded(byte[] machineCode, int address, int numberOfStatements) {
        this.machineCode = machineCode;
        this.address = address;
        this.numberOfStatements = numberOfStatements;
    }

    public byte[] getMachineCode() {
        return machineCode;
    }

    public int getAddress() {
        return address;
    }

    public int getNumberOfStatements() {
        return numberOfStatements;
    }
}
