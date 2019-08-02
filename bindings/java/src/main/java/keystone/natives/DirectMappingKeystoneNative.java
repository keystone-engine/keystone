/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.natives;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import keystone.*;
import keystone.jna.KeystoneTypeMapper;

import java.util.HashMap;
import java.util.Map;

/**
 * The class providing the native functions of Keystone using the Direct Mapping of JNA for best performance.
 * <p>
 * The original function prototypes are declared in the header file <i>keystone.h</i>.
 *
 * @see <a href="https://github.com/java-native-access/jna/blob/master/www/DirectMapping.md">JNA: Direct Mapping</a>
 */
public final class DirectMappingKeystoneNative {

    static {
        Map<String, Object> options = new HashMap<>();
        options.put(Library.OPTION_TYPE_MAPPER, new KeystoneTypeMapper());

        // Direct Mapping using JNA
        Native.register(NativeLibrary.getInstance("keystone", options));
    }

    /**
     * Private constructor to prevent any instantiation of the class.
     */
    private DirectMappingKeystoneNative() {
    }

    /**
     * Determine if the given architecture is supported by this library.
     * <p>
     * Native function prototype: <i>bool ks_arch_supported(ks_arch arch);</i>
     *
     * @param architecture architecture type
     * @return {@code true} if this library supports the given arch.
     */
    public static native boolean ks_arch_supported(KeystoneArchitecture architecture);

    /**
     * Assemble a string given its the buffer, size, start address and number
     * of instructions to be decoded.
     * This API dynamically allocate memory to contain assembled instruction.
     * Resulted array of bytes containing the machine code is put into @machineCode.
     * <p>
     * On failure, call {@link DirectMappingKeystoneNative#ks_errno} for error code.
     * <p>
     * NOTE 1: this API will automatically determine memory needed to contain
     * output bytes in *encoding.
     * <p>
     * NOTE 2: caller must free the allocated memory itself to avoid memory leaking.
     * <p>
     * Native function prototype: <i>int ks_asm(ks_engine *ks,
     * const char *string,
     * uint64_t address,
     * unsigned char **encoding, size_t *encoding_size,
     * size_t *stat_count);</i>
     *
     * @param engine             handle returned by ks_open()
     * @param assembly           NULL-terminated assembly string. Use ; or \n to separate statements.
     * @param address            address of the first assembly instruction, or 0 to ignore.
     * @param machineCodeBuffer  array of bytes containing encoding of input assembly string.
     *                           NOTE: *encoding will be allocated by this function, and should be freed
     *                           with ks_free() function.
     * @param machineCodeSize    size of machineCode
     * @param numberOfStatements number of statements successfully processed
     * @return 0 on success, or -1 on failure.
     */
    public static native int ks_asm(Pointer engine, String assembly, long address, PointerByReference machineCodeBuffer,
                                    IntByReference machineCodeSize, IntByReference numberOfStatements);

    /**
     * Close KS instance: MUST do to release the handle when it is not used anymore.
     * NOTE: this must be called only when there is no longer usage of Keystone.
     * The reason is this API releases some cached memory, thus access to any
     * Keystone API after ks_close() might crash your application.
     * After this, @engine is invalid, and no longer usable.
     * <p>
     * Native function prototype: <i>ks_err ks_close(ks_engine *ks);</i>
     *
     * @param engine pointer to a handle returned by ks_open().
     * @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum for detailed error).
     */
    public static native KeystoneError ks_close(Pointer engine);

    /**
     * Report the last error number when some API function fail.
     * Like glibc's errno, ks_errno might not retain its old error once accessed.
     * <p>
     * Native function prototype: <i>ks_err ks_errno(ks_engine *ks)</i>
     *
     * @param engine handle returned by ks_open()
     * @return error code of ks_err enum type {@link KeystoneError}
     */
    public static native KeystoneError ks_errno(Pointer engine);

    /**
     * Free memory allocated by ks_asm().
     * <p>
     * Native function prototype: <i>void ks_free(unsigned char *p)</i>
     *
     * @param machineCodeBuffer memory allocated in @encoding argument of ks_asm()
     */
    public static native void ks_free(Pointer machineCodeBuffer);

    /**
     * Create new instance of Keystone engine.
     * <p>
     * Native function prototype: <i>ks_err ks_open(ks_arch arch, int mode, ks_engine **ks);</i>
     *
     * @param architecture architecture type (KS_ARCH_*).
     * @param mode         hardware mode. This is combined of KS_MODE_*.
     * @param engine       pointer to ks_engine, which will be updated at return time.
     * @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum for detailed error).
     */
    public static native KeystoneError ks_open(KeystoneArchitecture architecture, KeystoneMode mode, PointerByReference engine);

    /**
     * Set option for Keystone engine at runtime.
     * <p>
     * Native function prototype: <i>err ks_option(ks_engine *ks, ks_opt_type type, size_t value);</i>
     *
     * @param engine handle returned by ks_open()
     * @param type   type of option to be set. See {@link KeystoneOptionType}
     * @param value  option value corresponding with @type
     * @return {@link KeystoneError#Ok} on success, or other value on failure.
     * Refer to {@link KeystoneError} enum for detailed error.
     */
    public static native KeystoneError ks_option(Pointer engine, KeystoneOptionType type, int value);

    /**
     * Set option for Keystone engine at runtime
     * <p>
     * Native function prototype: <i>err ks_option(ks_engine *ks, ks_opt_type type, size_t value);</i>
     *
     * @param engine   handle returned by ks_open()
     * @param type     ype of option to be set. See {@link KeystoneOptionType}
     * @param callback callback to resolve a unrecognized symbol.
     * @return {@link KeystoneError#Ok} on success, or other value on failure.
     * Refer to {@link KeystoneError} enum for detailed error.
     */
    public static native KeystoneError ks_option(Pointer engine, KeystoneOptionType type, SymbolResolverCallback callback);

    /**
     * Return a string describing given error code.
     * <p>
     * Native function prototype: <i>const char *ks_strerror(ks_err code);</i>
     *
     * @param errorCode error code.
     * @return returns a pointer to a string that describes the error code passed in the argument @errorCode.
     */
    public static native String ks_strerror(KeystoneError errorCode);

    /**
     * Returns combined API version & major and minor version numbers.
     * <p>
     * Native function prototype: <i>unsigned int ks_version(unsigned int *major, unsigned int *minor);</i>
     *
     * @param major The major number of API version.
     * @param minor The minor number of API version.
     * @return An hexadecimal number as (major << 8 | minor), which encodes both major & minor versions.
     */
    public static native int ks_version(IntByReference major, IntByReference minor);
}
