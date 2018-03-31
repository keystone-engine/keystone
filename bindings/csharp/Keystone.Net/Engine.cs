using System;
using System.Collections.Generic;
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
        private readonly bool throwOnError;
        private bool addedResolveSymbol;

        private readonly ResolverInternal internalImpl;
        private readonly List<Resolver> resolvers = new List<Resolver>();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool ResolverInternal(IntPtr symbol, ref ulong value);

        /// <summary>
        ///   Delegate for defining symbol resolvers.
        /// </summary>
        /// <param name="symbol">Symbol to resolve</param>
        /// <param name="value">Address</param>
        /// <returns>True if the symbol was recognized.</returns>
        public delegate bool Resolver(string symbol, ref ulong value);

        /// <summary>
        ///   Event raised when keystone is resolving a symbol.
        /// </summary>
        /// <remarks>This event requires Keystone 0.9.2 or higher.</remarks>
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
                        throw new InvalidOperationException($"Could not add symol resolver: {ErrorToString(err)}.");
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
                        throw new InvalidOperationException($"Could not remove symol resolver: {ErrorToString(err)}.");
                }

                resolvers.Remove(value);
            }
        }


        /// <summary>
        ///   Method used for symbol resolving.
        /// </summary>
        /// <param name="symbolPtr">Name of the symbol</param>
        /// <param name="value">Address</param>
        /// <returns>True if the symbol is recognized</returns>
        private bool SymbolResolver(IntPtr symbolPtr, ref ulong value)
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
        ///   Constructs the object with a given architecture and a given mode.
        /// </summary>
        /// <param name="architecture">Architecture</param>
        /// <param name="mode">Mode, i.e. endianess, word size etc.</param>
        /// <param name="throwOnKeystoneError">Throw when there are errors</param>
        /// <remarks>
        /// Some architectures are not supported.
        /// Check with <see cref="IsArchitectureSupported(Architecture)"/> if the engine
        /// support the architecture.
        /// </remarks>
        public Engine(Architecture architecture, Mode mode, bool throwOnKeystoneError = true)
        {
            internalImpl = SymbolResolver;
            throwOnError = throwOnKeystoneError;

            var result = NativeInterop.Open(architecture, (int)mode, ref engine);

            if (result != KeystoneError.KS_ERR_OK && throwOnKeystoneError)
                throw new InvalidOperationException($"Error while initializing keystone: {ErrorToString(result)}.");
        }

        /// <summary>
        ///   Sets an option in the engine.
        /// </summary>
        /// <param name="type">Type of option</param>
        /// <param name="value">Value</param>
        /// <returns>True is the option is correctly setted, False otherwise &amp;&amp; throwOnError is false.</returns>
        /// <exception cref="InvalidOperationException">If Keystone return an error &amp;&amp; throwOnError is true</exception>
        public bool SetOption(OptionType type, uint value)
        {
            var result = NativeInterop.SetOption(engine, (int)type, (IntPtr)value);

            if (result != KeystoneError.KS_ERR_OK)
            {
                if (throwOnError)
                    throw new InvalidOperationException($"Error while setting option in keystone: {ErrorToString(result)}.");
                return false;
            }

            return true;
        }

        /// <summary>
        ///   Returns a string associated with a given error code.
        /// </summary>
        /// <param name="result">Error code</param>
        /// <returns>The string</returns>
        public static string ErrorToString(KeystoneError result)
        {
            IntPtr error = NativeInterop.ErrorToString(result);
            if (error != IntPtr.Zero)
                return Marshal.PtrToStringAnsi(error);
            return string.Empty;
        }

        /// <summary>
        ///   Encodes given statements.
        /// </summary>
        /// <param name="toEncode">String that contains the statements to encode</param>
        /// <param name="address">Address of the first instruction.</param>
        /// <returns>Result of the assemble operation or null if it failed &amp;&amp; throwOnError is false.</returns>
        /// <exception cref="InvalidOperationException">If keystone return an error &amp;&amp; throwOnError is true</exception>
        public EncodedData Assemble(string toEncode, ulong address)
        {
            int result = NativeInterop.Assemble(engine,
                                                  toEncode,
                                                  address,
                                                  out IntPtr encoding,
                                                  out uint size,
                                                  out uint statementCount);

            if (result != 0)
            {
                if (throwOnError)
                    throw new InvalidOperationException($"Error while assembling {toEncode}: {ErrorToString(GetLastKeystoneError())}");
                return null;
            }

            byte[] buffer = new byte[size];

            Marshal.Copy(encoding, buffer, 0, (int)size);
            NativeInterop.Free(encoding);

            return new EncodedData(buffer, statementCount, address);
        }

        /// <summary>
        ///   Appends the result of an assemble to an existing collection of bytes.
        /// </summary>
        /// <param name="toEncode">String to encode</param>
        /// <param name="encoded">Collection of bytes</param>
        /// <param name="address">Address of the first instruction in input to this function</param>
        /// <param name="size">Size of the result of this operation</param>
        /// <param name="statements">Number of statement found</param>
        /// <returns>True if the compilation is successful, False otherwise &amp;&amp;throwOnError is False.</returns>
        /// <exception cref="ArgumentNullException">String to encode is null or collection is null</exception>
        /// <exception cref="ArgumentException">Collection is read-only</exception>
        /// <exception cref="InvalidOperationException">If keystone return an error &amp;&amp; throwOnError is true</exception>
        public bool AppendAssemble(string toEncode, ICollection<byte> encoded, ulong address, out int size, out int statements)
        {
            if (encoded == null)
                throw new ArgumentNullException(nameof(encoded));
            if (toEncode == null)
                throw new ArgumentNullException(nameof(toEncode));
            if (encoded.IsReadOnly)
                throw new ArgumentException("encoded collection can't be read-only.");

            var result = Assemble(toEncode, address);

            if (result != null)
            {
                foreach (var v in result.Buffer)
                    encoded.Add(v);

                size = result.Buffer.Length;
                statements = result.StatementCount;
                return true;
            }
            else
            {
                size = 0;
                statements = 0;
                return false;
            }
        }

        /// <summary>
        ///   Appends the result of an assemble to an existing collection of bytes.
        /// </summary>
        /// <param name="toEncode">String to encode</param>
        /// <param name="encoded">Collection of bytes</param>
        /// <param name="address">Address of the first instruction in input to this function</param>
        /// <param name="size">Size of the result of this operation</param>
        /// <returns>True if the compilation is successful, False otherwise &amp;&amp; throwOnError is True.</returns>
        /// <exception cref="ArgumentNullException">String to encode is null or collection is null</exception>
        /// <exception cref="ArgumentException">Collection is read-only</exception>
        /// <exception cref="InvalidOperationException">If keystone return an error &amp;&amp; throwOnError is true</exception>
        public bool AppendAssemble(string toEncode, ICollection<byte> encoded, ulong address, out int size)
        {
            return AppendAssemble(toEncode, encoded, address, out size, out _);
        }

        /// <summary>
        ///   Appends the result of an assemble to an existing collection of bytes.
        /// </summary>
        /// <param name="toEncode">String to encode</param>
        /// <param name="encoded">Collection of bytes</param>
        /// <param name="address">Address of the first instruction in input to this function</param>
        /// <returns>True if the compilation is successful, False otherwise &amp;&amp;throwOnError is True.</returns>
        /// <exception cref="ArgumentNullException">String to encode is null or collection is null</exception>
        /// <exception cref="ArgumentException">Collection is read-only</exception>
        /// <exception cref="InvalidOperationException">If keystone return an error &amp;&amp; throwOnError is true</exception>
        public bool AppendAssemble(string toEncode, ICollection<byte> encoded, ulong address)
        {
            return AppendAssemble(toEncode, encoded, address, out _, out _);
        }

        /// <summary>
        ///   Appends the result of an assemble to an existing collection of bytes.
        /// </summary>
        /// <param name="toEncode">String to encode</param>
        /// <param name="encoded">Collection of bytes</param>
        /// <returns>True if the compilation is successful, False otherwise &amp;&amp;throwOnError is True.</returns>
        /// <exception cref="ArgumentNullException">String to encode is null or collection is null</exception>
        /// <exception cref="ArgumentException">Collection is read-only</exception>
        /// <exception cref="InvalidOperationException">If keystone return an error &amp;&amp; throwOnError is true</exception>
        public bool AppendAssemble(string toEncode, ICollection<byte> encoded)
        {
            return AppendAssemble(toEncode, encoded, 0, out _, out _);
        }

        /// <summary>
        ///   Gets the last error for this instance.
        /// </summary>
        /// <returns>Last error</returns>
        /// <remarks>
        /// Might not retain its old error once accessed.
        /// </remarks>
        public KeystoneError GetLastKeystoneError()
        {
            return NativeInterop.GetLastKeystoneError(engine);
        }

        /// <summary>
        ///   Checks if an architecture is supported.
        /// </summary>
        /// <param name="architecture">Architecture</param>
        /// <returns>True if it is supported</returns>
        public static bool IsArchitectureSupported(Architecture architecture)
        {
            return NativeInterop.IsArchitectureSupported(architecture);
        }

        /// <summary>
        ///   Gets the version of the engine.
        /// </summary>
        /// <param name="major">Major</param>
        /// <param name="minor">Minor</param>
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
