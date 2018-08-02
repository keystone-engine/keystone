using System;
using System.Runtime.InteropServices;

namespace Keystone
{
    /// <summary>
    ///   Imported symbols for interop with keystone.dll.
    /// </summary>
    internal class NativeInterop
    {
        // This shouldn't be needed, even on Windows
        // /// <summary>
        // /// Taken from: http://stackoverflow.com/questions/10852634/using-a-32bit-or-64bit-dll-in-c-sharp-dllimport
        // /// </summary>
        // static NativeInterop()
        // {
        //     var myPath = new Uri(typeof(NativeInterop).Assembly.CodeBase).LocalPath;
        //     var myFolder = Path.GetDirectoryName(myPath);

        //     var is64 = IntPtr.Size == 8;
        //     var subfolder = is64 ? "\\win64\\" : "\\win32\\";

        //     string dllPosition = myFolder + subfolder + "keystone.dll";

        //     // If this file exist, load it. 
        //     // Otherwise let the marshaller load the appropriate file.
        //     if (File.Exists(dllPosition))
        //         LoadLibrary(dllPosition);
        // }

        // [DllImport("kernel32.dll")]
        // private static extern IntPtr LoadLibrary(string dllToLoad);
        
        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_version" )]
        internal static extern uint Version(ref uint major, ref uint minor);
        
        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_open")]
        internal static extern KeystoneError Open(Architecture arch, int mode, ref IntPtr ks);

        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_close")]
        internal static extern KeystoneError Close(IntPtr ks);

        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_free")]
        internal static extern void Free(IntPtr buffer);

        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_strerror")]
        internal static extern IntPtr ErrorToString(KeystoneError code);
        
        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_errno")]
        internal static extern KeystoneError GetLastKeystoneError(IntPtr ks);
        
        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_arch_supported")]
        internal static extern bool IsArchitectureSupported(Architecture arch);

        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_option")]
        internal static extern KeystoneError SetOption(IntPtr ks, int type, IntPtr value);

        [DllImport("keystone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ks_asm")]
        internal static extern int Assemble(IntPtr ks, 
            [MarshalAs(UnmanagedType.LPStr)] string toEncode, 
            ulong baseAddress, 
            out IntPtr encoding,
            out uint size, 
            out uint statements);
    }
}
