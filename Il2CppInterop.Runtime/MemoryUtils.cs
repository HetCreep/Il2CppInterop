using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Il2CppInterop.Common;
using Il2CppInterop.Common.XrefScans;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Runtime;

internal class MemoryUtils
{
    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    public static nint FindSignatureInModule(ProcessModule module, SignatureDefinition sigDef)
    {
        // On newer Unity (6000.x) the loaded GameAssembly maps pages as PAGE_NOACCESS / guard pages, so the raw
        // linear byte walk in FindSignatureInBlock dereferences protected memory and throws AccessViolationException
        // (an unrecoverable, process-fatal CSE) before the caller's signature-exhaustion fallback can run. Temporarily
        // make every region of the module readable for the duration of the scan, then restore the original protections.
        // VirtualProtect/VirtualQuery are kernel32 (Windows-only) and PAGE_NOACCESS is a Windows page state, so this
        // workaround runs on Windows only; on other platforms fall back to the direct scan (the prior behaviour).
        List<MEMORY_BASIC_INFORMATION> protectedRegions = null;
        var onWindows = OperatingSystem.IsWindows();
        if (onWindows)
        {
            GetModuleRegions(module, out protectedRegions);
            SetModuleRegions(protectedRegions, PAGE_EXECUTE_READWRITE);
        }
        nint ptr;
        try
        {
            ptr = FindSignatureInBlock(
                module.BaseAddress,
                module.ModuleMemorySize,
                sigDef.pattern,
                sigDef.mask,
                sigDef.offset
            );
        }
        finally
        {
            if (onWindows)
                SetModuleRegions(protectedRegions);
        }

        if (ptr != 0 && sigDef.xref)
            ptr = XrefScannerLowLevel.JumpTargets(ptr).FirstOrDefault();
        return ptr;
    }

    public static nint FindSignatureInBlock(nint block, long blockSize, string pattern, string mask, long sigOffset = 0)
    {
        return FindSignatureInBlock(block, blockSize, pattern.ToCharArray(), mask.ToCharArray(), sigOffset);
    }

    public static unsafe nint FindSignatureInBlock(nint block, long blockSize, char[] pattern, char[] mask,
        long sigOffset = 0)
    {
        for (long address = 0; address < blockSize; address++)
        {
            var found = true;
            for (uint offset = 0; offset < mask.Length; offset++)
                if (*(byte*)(address + block + offset) != (byte)pattern[offset] && mask[offset] != '?')
                {
                    found = false;
                    break;
                }

            if (found)
                return (nint)(address + block + sigOffset);
        }

        return 0;
    }

    // Walk the module's address space via VirtualQuery, collecting each region so its protection can be flipped to
    // readable for the scan and restored afterwards.
    internal static void GetModuleRegions(ProcessModule module, out List<MEMORY_BASIC_INFORMATION> protectedRegions)
    {
        protectedRegions = new List<MEMORY_BASIC_INFORMATION>();
        var moduleEndAddress = (IntPtr)((long)module.BaseAddress + module.ModuleMemorySize);
        var currentAddress = module.BaseAddress;
        while (currentAddress.ToInt64() < moduleEndAddress.ToInt64())
        {
            var result = VirtualQuery(currentAddress, out var memoryInfo,
                (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (result == 0)
                break; // error, or reached the end of the module's mapped memory

            protectedRegions.Add(memoryInfo);
            currentAddress = (IntPtr)((long)memoryInfo.BaseAddress + (long)memoryInfo.RegionSize);
        }
    }

    // Apply newProtection to every collected committed region (or restore each region's original Protect when
    // newProtection is null). Non-committed regions (MEM_FREE/MEM_RESERVE, Protect == 0) are skipped: VirtualProtect
    // rejects them and they hold no scannable bytes.
    internal static void SetModuleRegions(List<MEMORY_BASIC_INFORMATION> protectedRegions, uint? newProtection = null)
    {
        const uint MEM_COMMIT = 0x1000;
        foreach (var region in protectedRegions)
        {
            if (region.State != MEM_COMMIT)
                continue;

            var result = VirtualProtect(region.BaseAddress, (uint)region.RegionSize,
                newProtection ?? region.Protect, out _);
            if (!result)
                Logger.Instance.LogError("VirtualProtect failed for region 0x{Region:X} with error code {Error}",
                    region.BaseAddress.ToInt64(), Marshal.GetLastWin32Error());
        }
    }

    public struct SignatureDefinition
    {
        public string pattern;
        public string mask;
        public int offset;
        public bool xref;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
