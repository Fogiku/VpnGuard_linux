// Windows-only helper: create a USB boot option and set one-shot UEFI BootNext.
// Does not change BootOrder, Windows Boot Manager, Secure Boot or partitions.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class VpnGuardUefiBoot
{
    const string Global = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFirmwareType(out uint kind);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string s, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref Privilege value, uint length, IntPtr previous, IntPtr required);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFirmwareEnvironmentVariable(string name, string guid, byte[] data, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetFirmwareEnvironmentVariableEx(string name, string guid, byte[] data, uint size, uint attrs);
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct Privilege { public uint Count; public Luid Id; public uint Attributes; }
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static void Enable()
    {
        uint kind; Check(GetFirmwareType(out kind));
        if (kind != 2) throw new InvalidOperationException("UEFI required; Legacy BIOS is not supported.");
        IntPtr token; Check(OpenProcessToken(GetCurrentProcess(), 0x28, out token));
        try {
            Luid id; Check(LookupPrivilegeValue(null, "SeSystemEnvironmentPrivilege", out id));
            var p = new Privilege { Count=1, Id=id, Attributes=2 };
            Check(AdjustTokenPrivileges(token, false, ref p, 0, IntPtr.Zero, IntPtr.Zero));
            int err = Marshal.GetLastWin32Error(); if (err != 0) throw new Win32Exception(err);
        } finally { CloseHandle(token); }
    }
    static byte[] Read(string name)
    {
        byte[] b = new byte[65536];
        uint n = GetFirmwareEnvironmentVariable(name, Global, b, (uint)b.Length);
        if (n == 0) {
            int err = Marshal.GetLastWin32Error();
            if (err == 203 || err == 2) return null;
            throw new Win32Exception(err);
        }
        Array.Resize(ref b, (int)n); return b;
    }
    static void Write(string name, byte[] b)
    {
        Check(SetFirmwareEnvironmentVariableEx(name, Global, b, b == null ? 0 : (uint)b.Length, 7));
    }
    public static byte[] Option(uint partition, ulong start, ulong sectors, string guid)
    {
        byte[] file = Encoding.Unicode.GetBytes("\\EFI\\BOOT\\BOOTX64.EFI\0");
        byte[] path;
        using (var m = new MemoryStream()) using (var w = new BinaryWriter(m)) {
            w.Write((byte)4); w.Write((byte)1); w.Write((ushort)42);
            w.Write(partition); w.Write(start); w.Write(sectors);
            w.Write(new Guid(guid).ToByteArray()); w.Write((byte)2); w.Write((byte)2);
            w.Write((byte)4); w.Write((byte)4); w.Write((ushort)(4 + file.Length)); w.Write(file);
            w.Write(new byte[] { 0x7f, 0xff, 4, 0 }); path = m.ToArray();
        }
        using (var m = new MemoryStream()) using (var w = new BinaryWriter(m)) {
            w.Write((uint)1); w.Write((ushort)path.Length);
            w.Write(Encoding.Unicode.GetBytes("VpnGuard Ubuntu USB\0")); w.Write(path);
            return m.ToArray();
        }
    }
    public static string Arm(uint partition, ulong start, ulong sectors, string guid)
    {
        Enable();
        if (Read("BootNext") != null) throw new InvalidOperationException("BootNext is already set; refusing to overwrite another pending boot.");
        string name = null;
        for (int i = 0x9000; i <= 0xfffe; i++) {
            string candidate = "Boot" + i.ToString("X4");
            if (Read(candidate) == null) { name=candidate; break; }
        }
        if (name == null) throw new InvalidOperationException("No free UEFI boot variable.");
        byte[] option = Option(partition, start, sectors, guid);
        bool nextWritten = false;
        try {
            Write(name, option);
            byte[] next = BitConverter.GetBytes(Convert.ToUInt16(name.Substring(4), 16));
            Write("BootNext", next); nextWritten = true;
            byte[] read = Read("BootNext");
            if (read == null || read.Length != 2 || read[0] != next[0] || read[1] != next[1])
                throw new IOException("Firmware did not retain BootNext.");
            return name;
        } catch {
            if (nextWritten) Write("BootNext", null);
            Write(name, null);
            throw;
        }
    }
    public static void Cancel(string name)
    {
        Enable();
        if (name == null || !System.Text.RegularExpressions.Regex.IsMatch(name, "^Boot[0-9A-F]{4}$"))
            throw new ArgumentException("Invalid boot option.");
        byte[] option=Read(name);
        byte[] title=Encoding.Unicode.GetBytes("VpnGuard Ubuntu USB\0");
        if (option == null || option.Length < 6 + title.Length) throw new InvalidOperationException("Option not found.");
        for (int i=0;i<title.Length;i++) if (option[6+i] != title[i]) throw new InvalidOperationException("Not a VpnGuard option.");
        byte[] next=Read("BootNext");
        if (next != null && next.Length == 2 && BitConverter.ToUInt16(next,0) == Convert.ToUInt16(name.Substring(4),16))
            Write("BootNext", null);
        Write(name, null);
    }
}
