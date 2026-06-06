using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Il2CppInterop.Common.XrefScans;

namespace Il2CppInterop.Runtime;

internal class MemoryUtils
{
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_GUARD = 0x100;

    // Protections that permit reading: READONLY|READWRITE|WRITECOPY|EXECUTE_READ|EXECUTE_READWRITE|EXECUTE_WRITECOPY.
    private const uint PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    public static nint FindSignatureInModule(ProcessModule module, SignatureDefinition sigDef)
    {
        // On newer Unity (6000.x) the loaded GameAssembly maps some pages PAGE_NOACCESS / guard pages; the raw
        // linear byte walk in FindSignatureInBlock dereferences them and throws a fatal AccessViolationException.
        // Use VirtualQuery to enumerate the module's regions and scan only the readable committed ones, skipping
        // the rest -- without ever modifying page protections. VirtualQuery is kernel32 (Windows-only); off Windows
        // (where this guard-page issue does not arise) fall back to the plain whole-module scan.
        nint ptr = 0;
        if (OperatingSystem.IsWindows())
        {
            GetModuleRegions(module, out var regions);
            foreach (var region in regions)
            {
                if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) != 0 ||
                    (region.Protect & PAGE_READABLE) == 0)
                    continue;
                ptr = FindSignatureInBlock(region.BaseAddress, region.RegionSize.ToInt64(),
                    sigDef.pattern, sigDef.mask, sigDef.offset);
                if (ptr != 0)
                    break;
            }
        }
        else
        {
            ptr = FindSignatureInBlock(module.BaseAddress, module.ModuleMemorySize,
                sigDef.pattern, sigDef.mask, sigDef.offset);
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

    // Walk the module's address space via VirtualQuery, collecting each region so the scan can pick the readable ones.
    internal static void GetModuleRegions(ProcessModule module, out List<MEMORY_BASIC_INFORMATION> regions)
    {
        regions = new List<MEMORY_BASIC_INFORMATION>();
        var moduleEndAddress = (IntPtr)((long)module.BaseAddress + module.ModuleMemorySize);
        var currentAddress = module.BaseAddress;
        while (currentAddress.ToInt64() < moduleEndAddress.ToInt64())
        {
            var result = VirtualQuery(currentAddress, out var memoryInfo,
                (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (result == 0)
                break; // error, or reached the end of the module's mapped memory

            regions.Add(memoryInfo);
            currentAddress = (IntPtr)((long)memoryInfo.BaseAddress + (long)memoryInfo.RegionSize);
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
