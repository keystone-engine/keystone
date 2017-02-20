using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Keystone
{
    public class Engine
    {
        private IntPtr engine = IntPtr.Zero;

        public IntPtr Pointer()
        {
            return engine;
        }

        public bool IsReady()
        {
            return (engine != IntPtr.Zero);
        }

        public uint Version(ref int major, ref int minor)
        {
            return (uint) Import.ks_version(ref major, ref minor);
        }

        public bool IsArchSupported(Constants.ks_arch arch)
        {
            return Import.ks_arch_supported(arch);
        }

        public Constants.ks_err Open(Constants.ks_arch arch, Constants.ks_mode mode)
        {
            return Import.ks_open(arch, (int) mode, ref engine);
        }

        public Constants.ks_err Close()
        {
            return Import.ks_close(engine);
        }

        public Constants.ks_err Errno()
        {
            return Import.ks_errno(engine);
        }

        public string StrError(Constants.ks_err code)
        {
            return Import.ks_strerror(code);
        }

        public Constants.ks_err SetSymbolResolver(Constants.ks_sym_resolver resolver)
        {
            return Import.ks_option(engine, Constants.ks_opt_type.KS_OPT_SYM_RESOLVER, Marshal.GetFunctionPointerForDelegate(resolver));
        }

        public Constants.ks_err SetSyntax(Constants.ks_opt_value syntax)
        {
            return Import.ks_option(engine, Constants.ks_opt_type.KS_OPT_SYNTAX, new IntPtr((int) syntax));
        }

        public int Assemble(string str, UInt64 address, ref List<byte> encoding, ref ulong statCount)
        {
            IntPtr encodingPtr = IntPtr.Zero;
            UIntPtr encodingSize = UIntPtr.Zero;
            UIntPtr statCountPtr = UIntPtr.Zero;

            int ret = Import.ks_asm(engine, str, address, out encodingPtr, out encodingSize, out statCountPtr);

            if (ret == 0)
            {
                statCount = statCountPtr.ToUInt64();

                byte[] encoding_raw = new byte[encodingSize.ToUInt64()];
                Marshal.Copy(encodingPtr, encoding_raw, 0, encoding_raw.Length);

                // We want to add this to a dynamic array
                for (uint i = 0; i < encoding_raw.Length; i++)
                    encoding.Add(encoding_raw[i]);

                Free(encodingPtr);
            }

            return ret;
        }

        public int Assemble(string str, UInt64 address, ref List<byte> encoding)
        {
            IntPtr encodingPtr = IntPtr.Zero;
            UIntPtr encodingSize = UIntPtr.Zero;
            UIntPtr statCountPtr = UIntPtr.Zero;

            int ret = Import.ks_asm(engine, str, address, out encodingPtr, out encodingSize, out statCountPtr);

            if (ret == 0)
            {
                byte[] encoding_raw = new byte[encodingSize.ToUInt64()];
                Marshal.Copy(encodingPtr, encoding_raw, 0, encoding_raw.Length);

                // We want to add this to a dynamic array
                for (uint i = 0; i < encoding_raw.Length; i++)
                    encoding.Add(encoding_raw[i]);

                Free(encodingPtr);
            }

            return ret;
        }

        public void Free(IntPtr p)
        {
            Import.ks_free(p);
        }
    }
}
