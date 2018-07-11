/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.natives;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import keystone.KeystoneArchitecture;
import keystone.KeystoneError;
import keystone.KeystoneMode;

/**
 * Contract used by JNA to interoperate with the native C code of the library.
 */
public interface KeystoneNative extends Library {

    /**
     * Assemble a string given its the buffer, size, start address and number
     * of instructions to be decoded.
     * This API dynamically allocate memory to contain assembled instruction.
     * Resulted array of bytes containing the machine code is put into @machineCode.
     *
     * On failure, call {@link KeystoneNative#ks_errno} for error code.
     *
     * NOTE 1: this API will automatically determine memory needed to contain
     * output bytes in *encoding.
     *
     * NOTE 2: caller must free the allocated memory itself to avoid memory leaking.
     * @param engine handle returned by ks_open()
     * @param assembly NULL-terminated assembly string. Use ; or \n to separate statements.
     * @param address address of the first assembly instruction, or 0 to ignore.
     * @param machineCodeBuffer array of bytes containing encoding of input assembly string.
     *                    NOTE: *encoding will be allocated by this function, and should be freed
     *                    with ks_free() function.
     * @param machineCodeSize size of machineCode
     * @param numberOfStatements number of statements successfully processed
     * @return 0 on success, or -1 on failure.
     */
    int ks_asm(Pointer engine, String assembly, int address, PointerByReference machineCodeBuffer,
               IntByReference machineCodeSize, IntByReference numberOfStatements);

    /**
     * Report the last error number when some API function fail.
     * Like glibc's errno, ks_errno might not retain its old error once accessed.
     *
     * @param engine handle returned by ks_open()
     * @return error code of ks_err enum type {@link KeystoneError}
     */
    KeystoneError ks_errno(Pointer engine);

    /**
     * Free memory allocated by ks_asm().
     *
     * @param machineCodeBuffer memory allocated in @encoding argument of ks_asm()
     */
    void ks_free(Pointer machineCodeBuffer);

    /**
     * Returns combined API version & major and minor version numbers.
     *
     * @param major The major number of API version.
     * @param minor The minor number of API version.
     * @return An hexadecimal number as (major << 8 | minor), which encodes both major & minor versions.
     */
    int ks_version(IntByReference major, IntByReference minor);

    /**
     * Close KS instance: MUST do to release the handle when it is not used anymore.
     * NOTE: this must be called only when there is no longer usage of Keystone.
     * The reason is this API releases some cached memory, thus access to any
     * Keystone API after ks_close() might crash your application.
     * After this, @engine is invalid, and no longer usable.
     *
     * @param engine pointer to a handle returned by ks_open().
     * @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum for detailed error).
     */
    KeystoneError ks_close(Pointer engine);

    /**
     * Create new instance of Keystone engine.
     *
     * @param architecture architecture type (KS_ARCH_*).
     * @param mode hardware mode. This is combined of KS_MODE_*.
     * @param engine pointer to ks_engine, which will be updated at return time.
     * @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum for detailed error).
     */
    // ks_err ks_open(ks_arch arch, int mode, ks_engine **ks);
    KeystoneError ks_open(KeystoneArchitecture architecture, KeystoneMode mode, PointerByReference engine);
}