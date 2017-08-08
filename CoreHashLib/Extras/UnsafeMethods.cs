//------------------------------------------------------------------------------
// <copyright file="UnsafeMethods.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Security;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Threading;
using System.Net.Sockets;

namespace System.Security.Cryptography
{
   

    [Flags]
    internal enum FormatMessageFlags : uint
    {
        
        FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
        //FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
        //FORMAT_MESSAGE_FROM_STRING = 0x00000400,
        FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
        FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
    }

    public static class UnsafeSystemNativeMethods
    {
        private const string KERNEL32 = "KERNEL32.dll";

        [DllImport(KERNEL32, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern unsafe SafeLoadLibrary LoadLibraryExW(string lpwLibFileName, [In] void* hFile, uint dwFlags);

        [DllImport(KERNEL32, ExactSpelling = true, SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern unsafe bool FreeLibrary(IntPtr hModule);

        [DllImport(KERNEL32, EntryPoint = "GetProcAddress", SetLastError = true, BestFitMapping = false)]
        internal extern static IntPtr GetProcAddress(SafeLoadLibrary hModule, string entryPoint);

        [DllImport(KERNEL32, CharSet = CharSet.Unicode)]
        internal extern static uint FormatMessage(
                                            FormatMessageFlags dwFlags,
                                            IntPtr lpSource,
                                            UInt32 dwMessageId,
                                            UInt32 dwLanguageId,
                                            ref IntPtr lpBuffer,
                                            UInt32 nSize,
                                            IntPtr vaArguments
            );

        [DllImport(KERNEL32, CharSet = CharSet.Unicode)]
        internal extern static uint LocalFree(IntPtr lpMem);

    }

    // <SecurityKernel Critical="True" Ring="0">
    // <SatisfiesLinkDemand Name="SafeHandleZeroOrMinusOneIsInvalid" />
    // </SecurityKernel>
    public sealed class SafeLoadLibrary : SafeHandleZeroOrMinusOneIsInvalid
    {
        private const string KERNEL32 = "kernel32.dll";
        private SafeLoadLibrary() : base(true) { }
        //private SafeLoadLibrary(bool ownsHandle) : base(ownsHandle) { }

        //internal static readonly SafeLoadLibrary Zero = new SafeLoadLibrary(false);
        public unsafe static SafeLoadLibrary LoadLibraryEx(string library)
        {
            var result = UnsafeSystemNativeMethods.LoadLibraryExW(library, null, 0);
            if (result.IsInvalid)
            {
                //NOTE:
                //IsInvalid tests the numeric value of the handle. 
                //SetHandleAsInvalid sets the handle as closed, so that further closing 
                //does not have to take place in the critical finalizer thread. 
                //
                //You would think that when you assign 0 or -1 to an instance of 
                //SafeHandleZeroOrMinusoneIsInvalid, the handle will not be closed, since after all it is invalid 
                //It turns out that the SafeHandleZetoOrMinusOneIsInvalid overrides only the IsInvalid() method
                //It does not do anything to automatically close it.
                //So we have to SetHandleAsInvalid --> Which means mark it closed -- so that
                //we will not eventually call CloseHandle on 0 or -1
                result.SetHandleAsInvalid();
            }
            return result;
        }
        protected override bool ReleaseHandle()
        {
            return UnsafeSystemNativeMethods.FreeLibrary(handle);
        }
    }


    // ==++==
    // 
    //   Copyright (c) Microsoft Corporation.  All rights reserved.
    // 
    // ==--==
    /*============================================================
    **
    ** Class: UnsafeNativeMethods
    **
    ============================================================*/
    
}

namespace Microsoft.Win32
{
    using Microsoft.Win32;
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.ConstrainedExecution;
    using System.Runtime.InteropServices;
    using System.Runtime.Serialization;
    using System.Runtime.Versioning;
    using System.Security;
    using System.Security.Permissions;
    using System.Text;
    using System.Diagnostics.Tracing;
    using System.ComponentModel;
    using static System.Security.Cryptography.BCryptNative;

    [SuppressUnmanagedCodeSecurityAttribute()]
    internal static class UnsafeNativeMethods
    {
        // 
        // BOOL GetFileMUIPath(
        //   DWORD  dwFlags,
        //   PCWSTR  pcwszFilePath,
        //   PWSTR  pwszLanguage,
        //   PULONG  pcchLanguage,
        //   PWSTR  pwszFileMUIPath,
        //   PULONG  pcchFileMUIPath,
        //   PULONGLONG  pululEnumerator
        // );
        // 
        [DllImport("KERNEL32", EntryPoint = "GetFileMUIPath", SetLastError = true, ExactSpelling = true)]
        [ResourceExposure(ResourceScope.Machine)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileMUIPath(
                                     int flags,
                                     [MarshalAs(UnmanagedType.LPWStr)]
                                     String filePath,
                                     [MarshalAs(UnmanagedType.LPWStr)]
                                     StringBuilder language,
                                     ref int languageLength,
                                     [MarshalAs(UnmanagedType.LPWStr)]
                                     StringBuilder fileMuiPath,
                                     ref int fileMuiPathLength,
                                     ref Int64 enumerator);


        [DllImport("USER32", EntryPoint = "LoadStringW", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        [ResourceExposure(ResourceScope.Process)]
        internal static extern int LoadString(SafeLibraryHandle handle, int id, StringBuilder buffer, int bufferLength);

        [DllImport("KERNEL32", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        [ResourceExposure(ResourceScope.Machine)]
        internal static extern SafeLibraryHandle LoadLibraryEx(string libFilename, IntPtr reserved, int flags);

        [DllImport("KERNEL32", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        [ResourceExposure(ResourceScope.None)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        internal static extern bool FreeLibrary(IntPtr hModule);


        [SecurityCritical]
        [SuppressUnmanagedCodeSecurityAttribute()]
        internal static unsafe class ManifestEtw
        {
            //
            // Constants error coded returned by ETW APIs
            //

            // The event size is larger than the allowed maximum (64k - header).
            internal const int ERROR_ARITHMETIC_OVERFLOW = 534;

            // Occurs when filled buffers are trying to flush to disk, 
            // but disk IOs are not happening fast enough. 
            // This happens when the disk is slow and event traffic is heavy. 
            // Eventually, there are no more free (empty) buffers and the event is dropped.
            internal const int ERROR_NOT_ENOUGH_MEMORY = 8;

            internal const int ERROR_MORE_DATA = 0xEA;
            internal const int ERROR_NOT_SUPPORTED = 50;
            internal const int ERROR_INVALID_PARAMETER = 0x57;

            //
            // ETW Methods
            //

            internal const int EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0;
            internal const int EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
            internal const int EVENT_CONTROL_CODE_CAPTURE_STATE = 2;


        }
#if FEATURE_COMINTEROP
        [SecurityCritical]
        [DllImport("combase.dll", PreserveSig = true)]
        internal static extern int RoGetActivationFactory(
            [MarshalAs(UnmanagedType.HString)] string activatableClassId,
            [In] ref Guid iid,
            [Out,MarshalAs(UnmanagedType.IInspectable)] out Object factory);
#endif

    }
}
// ==++==
// 
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// 
// ==--==
//
// Abstract derivations of SafeHandle designed to provide the common
// functionality supporting Win32 handles. More specifically, they describe how
// an invalid handle looks (for instance, some handles use -1 as an invalid
// handle value, others use 0).
//
// Further derivations of these classes can specialise this even further (e.g.
// file or registry handles).
// 
//

namespace Microsoft.Win32.SafeHandles
{
    using System;
    using System.Runtime.InteropServices;
    using System.Runtime.CompilerServices;
    using System.Security.Permissions;
    using System.Runtime.ConstrainedExecution;

    // Class of safe handle which uses only -1 as an invalid handle.
    [System.Security.SecurityCritical]  // auto-generated_required
#if !FEATURE_CORECLR
    [SecurityPermission(SecurityAction.InheritanceDemand, UnmanagedCode = true)]
#endif
    public abstract class SafeHandleMinusOneIsInvalid : SafeHandle
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected SafeHandleMinusOneIsInvalid(bool ownsHandle) : base(new IntPtr(-1), ownsHandle)
        {
        }

#if FEATURE_CORECLR
        // A default constructor is needed to satisfy CoreCLR inheritence rules. It should not be called at runtime
        protected SafeHandleMinusOneIsInvalid()
        {
            throw new NotImplementedException();
        }
#endif // FEATURE_CORECLR

        public override bool IsInvalid
        {
            [System.Security.SecurityCritical]
            get { return handle == new IntPtr(-1); }
        }
    }

    // Class of critical handle which uses 0 or -1 as an invalid handle.
    [System.Security.SecurityCritical]  // auto-generated_required
#if !FEATURE_CORECLR
    [SecurityPermission(SecurityAction.InheritanceDemand, UnmanagedCode = true)]
#endif
    public abstract class CriticalHandleZeroOrMinusOneIsInvalid : CriticalHandle
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected CriticalHandleZeroOrMinusOneIsInvalid() : base(IntPtr.Zero)
        {
        }

        public override bool IsInvalid
        {
            [System.Security.SecurityCritical]
            get { return handle == null || handle == new IntPtr(-1); }
        }
    }

    // Class of critical handle which uses only -1 as an invalid handle.
    [System.Security.SecurityCritical]  // auto-generated_required
#if !FEATURE_CORECLR
    [SecurityPermission(SecurityAction.InheritanceDemand, UnmanagedCode = true)]
#endif
    public abstract class CriticalHandleMinusOneIsInvalid : CriticalHandle
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected CriticalHandleMinusOneIsInvalid() : base(new IntPtr(-1))
        {
        }

        public override bool IsInvalid
        {
            [System.Security.SecurityCritical]
            get { return handle == new IntPtr(-1); }
        }
    }

}