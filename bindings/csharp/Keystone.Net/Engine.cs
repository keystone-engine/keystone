using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Keystone
{
    /// <summary>
    ///   Represents a Keystone engine.
    /// </summary>
    public sealed class Engine : IDisposable
    {
        private IntPtr engine = IntPtr.Zero;
        private bool addedResolveSymbol;

        private readonly ResolverInternal internalImpl;
        private readonly List<Resolver> resolvers = new List<Resolver>();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool ResolverInternal(IntPtr symbol, ref ulong value);


        /// <summary>
        ///   Gets or sets a value that represents whether a <see cref="KeystoneException" />
        ///   should be thrown on error.
        /// </summary>
        public bool ThrowOnError { get; set; }

        /// <summary>
        ///   Delegate for defining symbol resolvers.
        /// </summary>
        /// <param name="symbol">Symbol to resolve.</param>
        /// <param name="value">Address of taid symbol, if found.</param>
        /// <returns>Whether the symbol was recognized.</returns>
        public delegate bool Resolver(string symbol, ref ulong value);

        /// <summary>
        ///   Event raised when keystone is resolving a symbol.
        /// </summary>
        /// <remarks>This event is only available on Keystone 0.9.2 or higher.</remarks>
        public event Resolver ResolveSymbol
        {
            add
            {
                if (!addedResolveSymbol)
                {
                    KeystoneError err = NativeInterop.SetOption(engine, (int)OptionType.SYM_RESOLVER, Marshal.GetFunctionPointerForDelegate(internalImpl));

                    if (err == KeystoneError.KS_ERR_OK)
                        addedResolveSymbol = true;
                    else
                        throw new KeystoneException("Could not add symbol resolver", err);
                }

                resolvers.Add(value);
            }

            remove
            {
                if (addedResolveSymbol && resolvers.Count == 0)
                {
                    KeystoneError err = NativeInterop.SetOption(engine, (int)OptionType.SYM_RESOLVER, IntPtr.Zero);

                    if (err == KeystoneError.KS_ERR_OK)
                        addedResolveSymbol = false;
                    else
                        throw new KeystoneException("Could not remove symbol resolver", err);
                }

                resolvers.Remove(value);
            }
        }

        /// <summary>
        ///   Method used for symbol resolving.
        /// </summary>
        /// <param name="symbolPtr">Pointer to the name of the symbol.</param>
        /// <param name="value">Address of the symbol, if found.</param>
        /// <returns>Whether the symbol could be recognized.</returns>
        private bool ResolveSymbolInternal(IntPtr symbolPtr, ref ulong value)
        {
            string symbol = Marshal.PtrToStringAnsi(symbolPtr);

            foreach (Resolver item in resolvers)
            {
                bool result = item(symbol, ref value);
                if (result)
                    return true;
            }

            return false;
        }

        /// <summary>
        ///   Constructs the engine with a given architecture and a given mode.
        /// </summary>
        /// <param name="architecture">The target architecture.</param>
        /// <param name="mode">The mode, i.e. endianness, word size etc.</param>
        /// <remarks>
        ///   Some architectures are not supported.
        ///   Check with <see cref="IsArchitectureSupported(Architecture)"/> if the engine
        ///   supports the target architecture.
        /// </remarks>
        public Engine(Architecture architecture, Mode mode)
        {
            internalImpl = ResolveSymbolInternal;

            var result = NativeInterop.Open(architecture, (int)mode, ref engine);

            if (result != KeystoneError.KS_ERR_OK)
                throw new KeystoneException("Error while initializing keystone", result);
        }

        /// <summary>
        ///   Sets an option in the engine.
        /// </summary>
        /// <param name="type">Type of the option.</param>
        /// <param name="value">Value it the option.</param>
        /// <returns>Whether the option was correctly set.</returns>
        /// <exception cref="KeystoneException">An error encountered when setting the option.</exception>
        public bool SetOption(OptionType type, uint value)
        {
            var result = NativeInterop.SetOption(engine, (int)type, (IntPtr)value);

            if (result != KeystoneError.KS_ERR_OK)
            {
                if (ThrowOnError)
                    throw new KeystoneException("Error while setting option", result);

                return false;
            }

            return true;
        }

        /// <summary>
        ///   Encodes the given statement(s).
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode.</param>
        /// <param name="address">Address of the first instruction to encode.</param>
        /// <param name="size">Size of the buffer produced by the operation.</param>
        /// <param name="statementCount">Number of statements found and encoded.</param>
        /// <returns>Result of the operation, or <c>null</c> if it failed and <see cref="ThrowOnError" /> is <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">A null argument was given.</exception>
        /// <exception cref="KeystoneException">An error encountered when encoding the instructions.</exception>
        public byte[] Assemble(string toEncode, ulong address, out int size, out int statementCount)
        {
            if (toEncode == null)
                throw new ArgumentNullException(nameof(toEncode));

            int result = NativeInterop.Assemble(engine,
                                                toEncode,
                                                address,
                                                out IntPtr encoding,
                                                out uint size_,
                                                out uint statementCount_);
                                                
            if (result != 0)
            {
                if (ThrowOnError)
                    throw new KeystoneException("Error while assembling instructions", GetLastKeystoneError());

                size = statementCount = 0;

                return null;
            }

            size = (int)size_;
            statementCount = (int)statementCount_;

            byte[] buffer = new byte[size];

            Marshal.Copy(encoding, buffer, 0, size);
            NativeInterop.Free(encoding);

            return buffer;
        }

        /// <summary>
        ///   Encodes the given statement(s).
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode.</param>
        /// <param name="address">Address of the first instruction to encode.</param>
        /// <returns>Result of the operation, or <c>null</c> if it failed and <see cref="ThrowOnError" /> is <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">A null argument was given.</exception>
        /// <exception cref="KeystoneException">An error encountered when encoding the instructions.</exception>
        public EncodedData Assemble(string toEncode, ulong address)
        {
            byte[] buffer = Assemble(toEncode, address, out int size, out int statementCount);

            if (buffer == null)
                return null;

            return new EncodedData(buffer, statementCount, address);
        }

        /// <summary>
        ///   Encodes the given statement(s) into the given buffer.
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode.</param>
        /// <param name="address">Address of the first instruction to encode.</param>
        /// <param name="buffer">Buffer into which the data shall be written.</param>
        /// <param name="index">Index into the buffer after which the data shall be written.</param>
        /// <param name="statementCount">Number of statements found and encoded.</param>
        /// <returns>Size of the data writen by the operation., or <c>0</c> if it failed and <see cref="ThrowOnError" /> is <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">A null argument was given.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The provided index is invalid.</exception>
        /// <exception cref="KeystoneException">An error encountered when encoding the instructions.</exception>
        public int Assemble(string toEncode, ulong address, byte[] buffer, int index, out int statementCount)
        {
            if (toEncode == null)
                throw new ArgumentNullException(nameof(toEncode));
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (index < 0 || index >= buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(buffer));

            int result = NativeInterop.Assemble(engine,
                                                toEncode,
                                                address,
                                                out IntPtr encoding,
                                                out uint size_,
                                                out uint statementCount_);

            int size = (int)size_;

            statementCount = (int)statementCount_;

            if (result != 0)
            {
                if (ThrowOnError)
                    throw new KeystoneException("Error while assembling instructions", GetLastKeystoneError());

                return 0;
            }

            Marshal.Copy(encoding, buffer, index, size);
            NativeInterop.Free(encoding);

            return size;
        }

        /// <summary>
        ///   Encodes the given statement(s) into the given buffer.
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode.</param>
        /// <param name="address">Address of the first instruction to encode.</param>
        /// <param name="buffer">Buffer into which the data shall be written.</param>
        /// <param name="index">Index into the buffer after which the data shall be written.</param>
        /// <returns>Size of the data writen by the operation., or <c>0</c> if it failed and <see cref="ThrowOnError" /> is <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">A null argument was given.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The provided index is invalid.</exception>
        /// <exception cref="KeystoneException">An error encountered when encoding the instructions.</exception>
        public int Assemble(string toEncode, ulong address, byte[] buffer, int index)
        {
            return Assemble(toEncode, address, buffer, index, out _);
        }

        /// <summary>
        ///   Encodes the given statement(s) into the given stream.
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode.</param>
        /// <param name="address">Address of the first instruction to encode.</param>
        /// <param name="stream">Buffer into which the data shall be written.</param>
        /// <param name="size">Size of the buffer produced by the operation.</param>
        /// <param name="statementCount">Number of statements found and encoded.</param>
        /// <returns><c>true</c> on success, or <c>false</c> if it failed and <see cref="ThrowOnError" /> is <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">A null argument was given.</exception>
        /// <exception cref="KeystoneException">An error encountered when encoding the instructions.</exception>
        public bool Assemble(string toEncode, ulong address, Stream stream, out int size, out int statementCount)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] enc = Assemble(toEncode, address, out size, out statementCount);

            if (enc == null)
                return false;

            stream.Write(enc, 0, size);

            return true;
        }

        /// <summary>
        ///   Encodes the given statement(s) into the given stream.
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode.</param>
        /// <param name="address">Address of the first instruction to encode.</param>
        /// <param name="stream">Buffer into which the data shall be written.</param>
        /// <param name="size">Size of the buffer produced by the operation.</param>
        /// <returns><c>true</c> on success, or <c>false</c> if it failed and <see cref="ThrowOnError" /> is <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">A null argument was given.</exception>
        /// <exception cref="KeystoneException">An error encountered when encoding the instructions.</exception>
        public bool Assemble(string toEncode, ulong address, Stream stream, out int size)
        {
            return Assemble(toEncode, address, stream, out size, out _);
        }

        /// <summary>
        ///   Encodes the given statement(s) into the given stream.
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode.</param>
        /// <param name="address">Address of the first instruction to encode.</param>
        /// <param name="stream">Buffer into which the data shall be written.</param>
        /// <returns><c>true</c> on success, or <c>false</c> if it failed and <see cref="ThrowOnError" /> is <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">A null argument was given.</exception>
        /// <exception cref="KeystoneException">An error encountered when encoding the instructions.</exception>
        public bool Assemble(string toEncode, ulong address, Stream stream)
        {
            return Assemble(toEncode, address, stream, out _, out _);
        }

        /// <summary>
        ///   Gets the last error for this instance.
        /// </summary>
        /// <returns>The last error code.</returns>
        /// <remarks>
        ///   It might not retain its old error once accessed.
        /// </remarks>
        public KeystoneError GetLastKeystoneError()
        {
            return NativeInterop.GetLastKeystoneError(engine);
        }

        /// <summary>
        ///   Returns the string associated with a given error code.
        /// </summary>
        public static string ErrorToString(KeystoneError code)
        {
            IntPtr error = NativeInterop.ErrorToString(code);

            if (error != IntPtr.Zero)
                return Marshal.PtrToStringAnsi(error);

            return string.Empty;
        }

        /// <summary>
        ///   Checks if the given architecture is supported.
        /// </summary>
        public static bool IsArchitectureSupported(Architecture architecture)
        {
            return NativeInterop.IsArchitectureSupported(architecture);
        }

        /// <summary>
        ///   Gets the version of the engine.
        /// </summary>
        /// <param name="major">Major version number.</param>
        /// <param name="minor">Minor version number.</param>
        /// <returns>Unique identifier for this version.</returns>
        public static uint GetKeystoneVersion(ref uint major, ref uint minor)
        {
            return NativeInterop.Version(ref major, ref minor);
        }

        /// <summary>
        ///   Releases the engine.
        /// </summary>
        public void Dispose()
        {
            IntPtr currentEngine = Interlocked.Exchange(ref engine, IntPtr.Zero);

            if (currentEngine != IntPtr.Zero)
                NativeInterop.Close(currentEngine);
        }
    }
}
