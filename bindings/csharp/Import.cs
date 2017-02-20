using System;
using System.Runtime.InteropServices;

namespace Keystone
{
    class Import
    {
        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ks_version(ref int major, ref int minor);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ks_arch_supported(Constants.ks_arch arch);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern Constants.ks_err ks_open(Constants.ks_arch arch, int mode, ref IntPtr ks);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern Constants.ks_err ks_close(IntPtr ks);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern Constants.ks_err ks_errno(IntPtr ks);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern string ks_strerror(Constants.ks_err code);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern Constants.ks_err ks_option(IntPtr ks, Constants.ks_opt_type type, IntPtr value);

        [DllImport("keystone.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ks_asm(IntPtr ks, 
            [MarshalAs(UnmanagedType.LPStr)] string str,
            [MarshalAs(UnmanagedType.U8)] UInt64 address, 
            [MarshalAs(UnmanagedType.SysInt)] out IntPtr encoding,
            [MarshalAs(UnmanagedType.SysUInt)] out UIntPtr encodingSize,
            [MarshalAs(UnmanagedType.SysUInt)] out UIntPtr stat_count);

        [DllImport("keystone.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void ks_free([MarshalAs(UnmanagedType.SysInt)] IntPtr p);
    }
}
