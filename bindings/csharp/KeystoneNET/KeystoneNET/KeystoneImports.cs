using System;
using System.IO;
using System.Runtime.InteropServices;

namespace KeystoneNET
{
    /// <summary>
    /// Imports for keystone.dll
    /// </summary>
    internal class KeystoneImports
    {
        /// <summary>
        /// Taken from: http://stackoverflow.com/questions/10852634/using-a-32bit-or-64bit-dll-in-c-sharp-dllimport
        /// </summary>
        static KeystoneImports()
        {
            var myPath = new Uri(typeof(KeystoneImports).Assembly.CodeBase).LocalPath;
            var myFolder = Path.GetDirectoryName(myPath);

            var is64 = IntPtr.Size == 8;
            var subfolder = is64 ? "\\win64\\" : "\\win32\\";

            string dllPosition = myFolder + subfolder + "keystone.dll";

            // If this file exist, load it. 
            // Otherwise let the marshaller load the appropriate file.
            if (File.Exists(dllPosition))
                LoadLibrary(dllPosition);
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllToLoad);
        
        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_version" )]
        internal extern static uint Version(ref uint major, ref uint minor);
        
        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_open")]
        internal extern static KeystoneError Open(KeystoneArchitecture arch, int mode, ref IntPtr ks);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_close")]
        internal extern static KeystoneError Close(IntPtr ks);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_free")]
        internal extern static void Free(IntPtr buffer);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_strerror")]
        internal extern static IntPtr ErrorToString(KeystoneError code);
        
        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_errno")]
        internal extern static KeystoneError GetLastKeystoneError(IntPtr ks);
        
        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_arch_supported")]
        internal extern static bool IsArchitectureSupported(KeystoneArchitecture arch);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_option")]
        internal extern static KeystoneError SetOption(IntPtr ks, KeystoneOptionType type, IntPtr value);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_asm")]
        internal extern static int Assemble(IntPtr ks, 
            [MarshalAs(UnmanagedType.LPStr)] string toEncode, 
            ulong baseAddress, 
            out IntPtr encoding,
            out uint size, 
            out uint statements);
    }
}
