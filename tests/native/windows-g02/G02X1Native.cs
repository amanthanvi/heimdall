// G02X1Native.cs: P/Invoke helpers for tests/native/windows-g02 (harness code, not product code).
// Compiled at run time by Add-Type (Windows PowerShell 5.1 csc / PowerShell 7 Roslyn): C# 5 syntax only.
//
//   X1Pty    : a pseudoconsole (CreatePseudoConsole) with a child attached; the child optionally gets
//              explicit std handles (files) while staying attached to the pseudoconsole. Output is drained
//              on a background thread. No window is created.
//   X1Ctrl   : FreeConsole / AttachConsole(pid) / GenerateConsoleCtrlEvent, for the separate sender process
//              (Send-ConsoleCtrl.ps1); a process may attach to one console only, hence a separate process.
//              The sender ignores CTRL_C (NULL handler) and swallows CTRL_BREAK (own handler) itself.
//   X1Proc   : WaitForSingleObject / GetExitCodeProcess on handles this harness owns.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class X1Api
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }
    [StructLayout(LayoutKind.Sequential)]
    public struct COORD { public short X, Y; }

    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000, CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const int STARTF_USESTDHANDLES = 0x100;
    public static readonly IntPtr PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = new IntPtr(0x00020016);
    public static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
    public const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3, CREATE_ALWAYS = 2;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags,
        IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(out IntPtr hRead, out IntPtr hWrite, IntPtr sa, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint flags, out IntPtr hPC);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int ResizePseudoConsole(IntPtr hPC, COORD size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void ClosePseudoConsole(IntPtr hPC);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value, IntPtr size, IntPtr prev, IntPtr retSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(IntPtr h, byte[] buf, int n, out int written, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(IntPtr h, byte[] buf, int n, out int read, IntPtr ov);
}

public sealed class X1Pty : IDisposable
{
    IntPtr hPC = IntPtr.Zero, inWrite = IntPtr.Zero, outRead = IntPtr.Zero, hProcess = IntPtr.Zero;
    readonly MemoryStream buf = new MemoryStream();
    readonly object gate = new object();
    Thread reader;
    public int Pid;
    public DateTime StartedUtc;
    public X1Screen Screen;
    int fed;
    // Feeds the output received so far into the screen model and returns its text (one line per row).
    public string ScreenText() { byte[] b = Snapshot(fed); fed += b.Length; Screen.Feed(b); return Screen.Text(); }
    public DateTime? ExitSeenUtc;

    // cmdline: full command line (application name taken from it). stdoutPath/stderrPath: when not null the
    // child gets STARTF_USESTDHANDLES with NUL stdin and these files as stdout/stderr (it stays attached to
    // the pseudoconsole for console control events); when null its std handles are the pseudoconsole.
    // StdMode (no redirect): 0 = leave std handles alone, 1 = STARTF_USESTDHANDLES with NULL handles,
    // 2 = clear this process's std handles (SetStdHandle NULL) around CreateProcess so the child cannot copy them.
    public static int StdMode = 1;
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetStdHandle(int n);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetStdHandle(int n, IntPtr h);

    public static X1Pty Start(string cmdline, string cwd, short cols, short rows, string stdoutPath, string stderrPath)
    {
        X1Pty p = new X1Pty();
        p.Screen = new X1Screen(cols, rows);
        IntPtr inRead, outWrite;
        if (!X1Api.CreatePipe(out inRead, out p.inWrite, IntPtr.Zero, 0)) throw Fail("CreatePipe(in)");
        if (!X1Api.CreatePipe(out p.outRead, out outWrite, IntPtr.Zero, 0)) throw Fail("CreatePipe(out)");
        X1Api.COORD sz = new X1Api.COORD(); sz.X = cols; sz.Y = rows;
        int hr = X1Api.CreatePseudoConsole(sz, inRead, outWrite, 0, out p.hPC);
        if (hr != 0) throw new InvalidOperationException("CreatePseudoConsole hr=0x" + hr.ToString("x8"));
        X1Api.CloseHandle(inRead); X1Api.CloseHandle(outWrite);
        p.reader = new Thread(p.ReadLoop); p.reader.IsBackground = true; p.reader.Start();

        // PowerShell passes $null to a .NET string parameter as "": treat empty as absent.
        if (string.IsNullOrEmpty(stdoutPath)) stdoutPath = null;
        if (string.IsNullOrEmpty(stderrPath)) stderrPath = null;
        bool redirect = stdoutPath != null;
        List<IntPtr> inheritable = new List<IntPtr>();
        X1Api.STARTUPINFOEX si = new X1Api.STARTUPINFOEX();
        si.StartupInfo.cb = Marshal.SizeOf(typeof(X1Api.STARTUPINFOEX));
        if (redirect)
        {
            X1Api.SECURITY_ATTRIBUTES sa = new X1Api.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(X1Api.SECURITY_ATTRIBUTES)); sa.bInheritHandle = 1;
            IntPtr hin = X1Api.CreateFileW("NUL", X1Api.GENERIC_READ, X1Api.FILE_SHARE_READ | X1Api.FILE_SHARE_WRITE, ref sa, X1Api.OPEN_EXISTING, 0, IntPtr.Zero);
            IntPtr hout = X1Api.CreateFileW(stdoutPath, X1Api.GENERIC_WRITE, X1Api.FILE_SHARE_READ, ref sa, X1Api.CREATE_ALWAYS, 0, IntPtr.Zero);
            IntPtr herr = X1Api.CreateFileW(stderrPath ?? "NUL", X1Api.GENERIC_WRITE, X1Api.FILE_SHARE_READ | X1Api.FILE_SHARE_WRITE, ref sa, stderrPath == null ? X1Api.OPEN_EXISTING : X1Api.CREATE_ALWAYS, 0, IntPtr.Zero);
            if (hin == new IntPtr(-1) || hout == new IntPtr(-1) || herr == new IntPtr(-1)) throw Fail("CreateFileW(std handles)");
            si.StartupInfo.dwFlags = X1Api.STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = hin; si.StartupInfo.hStdOutput = hout; si.StartupInfo.hStdError = herr;
            inheritable.Add(hin); inheritable.Add(hout); inheritable.Add(herr);
        }
        int nattr = redirect ? 2 : 1;
        IntPtr size = IntPtr.Zero;
        X1Api.InitializeProcThreadAttributeList(IntPtr.Zero, nattr, 0, ref size);
        si.lpAttributeList = Marshal.AllocHGlobal(size);
        IntPtr handleArr = IntPtr.Zero;
        try
        {
            if (!X1Api.InitializeProcThreadAttributeList(si.lpAttributeList, nattr, 0, ref size)) throw Fail("InitializeProcThreadAttributeList");
            if (!X1Api.UpdateProcThreadAttribute(si.lpAttributeList, 0, X1Api.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, p.hPC, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                throw Fail("UpdateProcThreadAttribute(PSEUDOCONSOLE)");
            if (redirect)
            {
                handleArr = Marshal.AllocHGlobal(IntPtr.Size * inheritable.Count);
                for (int i = 0; i < inheritable.Count; i++) Marshal.WriteIntPtr(handleArr, i * IntPtr.Size, inheritable[i]);
                if (!X1Api.UpdateProcThreadAttribute(si.lpAttributeList, 0, X1Api.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArr, new IntPtr(IntPtr.Size * inheritable.Count), IntPtr.Zero, IntPtr.Zero))
                    throw Fail("UpdateProcThreadAttribute(HANDLE_LIST)");
            }
            X1Api.PROCESS_INFORMATION pi;
            StringBuilder cl = new StringBuilder(cmdline);
            p.StartedUtc = DateTime.UtcNow;
            if (!redirect && StdMode == 1) si.StartupInfo.dwFlags = X1Api.STARTF_USESTDHANDLES;
            IntPtr s0 = IntPtr.Zero, s1 = IntPtr.Zero, s2 = IntPtr.Zero;
            bool cleared = !redirect && StdMode == 2;
            if (cleared) { s0 = GetStdHandle(-10); s1 = GetStdHandle(-11); s2 = GetStdHandle(-12); SetStdHandle(-10, IntPtr.Zero); SetStdHandle(-11, IntPtr.Zero); SetStdHandle(-12, IntPtr.Zero); }
            bool okc;
            try { okc = X1Api.CreateProcessW(null, cl, IntPtr.Zero, IntPtr.Zero, redirect, X1Api.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, cwd, ref si, out pi); }
            finally { if (cleared) { SetStdHandle(-10, s0); SetStdHandle(-11, s1); SetStdHandle(-12, s2); } }
            if (!okc) throw Fail("CreateProcessW");
            p.hProcess = pi.hProcess; p.Pid = pi.dwProcessId;
            X1Api.CloseHandle(pi.hThread);
        }
        finally
        {
            X1Api.DeleteProcThreadAttributeList(si.lpAttributeList);
            Marshal.FreeHGlobal(si.lpAttributeList);
            if (handleArr != IntPtr.Zero) Marshal.FreeHGlobal(handleArr);
            foreach (IntPtr h in inheritable) X1Api.CloseHandle(h);
        }
        return p;
    }

    static Exception Fail(string step) { int e = Marshal.GetLastWin32Error(); return new InvalidOperationException(step + " failed: win32 " + e + " (" + new System.ComponentModel.Win32Exception(e).Message + ")"); }

    void ReadLoop()
    {
        byte[] b = new byte[8192];
        while (true)
        {
            int n;
            if (!X1Api.ReadFile(outRead, b, b.Length, out n, IntPtr.Zero) || n == 0) break;
            lock (gate) { buf.Write(b, 0, n); }
        }
    }

    public int Length { get { lock (gate) { return (int)buf.Length; } } }
    public byte[] Snapshot(int from)
    {
        lock (gate)
        {
            byte[] all = buf.ToArray();
            if (from >= all.Length) return new byte[0];
            byte[] r = new byte[all.Length - from]; Array.Copy(all, from, r, 0, r.Length); return r;
        }
    }
    public void Write(byte[] data)
    {
        int w; if (!X1Api.WriteFile(inWrite, data, data.Length, out w, IntPtr.Zero)) throw new System.ComponentModel.Win32Exception();
    }
    public int Resize(short cols, short rows) { ScreenText(); Screen.Resize(cols, rows); X1Api.COORD sz = new X1Api.COORD(); sz.X = cols; sz.Y = rows; return X1Api.ResizePseudoConsole(hPC, sz); }
    public bool HasExited { get { return X1Api.WaitForSingleObject(hProcess, 0) == 0; } }
    // Polls every 2 ms so the exit time is close to the real one; returns true if it exited.
    public bool WaitExit(int ms)
    {
        DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
        while (true)
        {
            if (X1Api.WaitForSingleObject(hProcess, 2) == 0) { if (!ExitSeenUtc.HasValue) ExitSeenUtc = DateTime.UtcNow; return true; }
            if (DateTime.UtcNow >= end) return false;
        }
    }
    public long ExitCode { get { uint c; return X1Api.GetExitCodeProcess(hProcess, out c) ? (long)c : -1; } }
    // Kernel-recorded exit time (UTC ticks) of an exited process, 0 if not available.
    public long ExitTicksUtc { get { long cr, ex, k, u; if (!HasExited || !X1Api.GetProcessTimes(hProcess, out cr, out ex, out k, out u)) return 0; return DateTime.FromFileTimeUtc(ex).Ticks; } }
    // Only for the process this object started (handle held since creation, so no PID reuse).
    public bool Kill() { return X1Api.TerminateProcess(hProcess, 0xDEAD); }
    public void Dispose()
    {
        if (hPC != IntPtr.Zero) { X1Api.ClosePseudoConsole(hPC); hPC = IntPtr.Zero; }
        if (inWrite != IntPtr.Zero) { X1Api.CloseHandle(inWrite); inWrite = IntPtr.Zero; }
        if (reader != null) reader.Join(3000);
        if (outRead != IntPtr.Zero) { X1Api.CloseHandle(outRead); outRead = IntPtr.Zero; }
        if (hProcess != IntPtr.Zero) { X1Api.CloseHandle(hProcess); hProcess = IntPtr.Zero; }
    }
}

public static class X1Ctrl
{
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    public delegate bool HandlerRoutine(uint ev);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);
    static readonly HandlerRoutine Swallow = delegate(uint ev) { return true; };   // static: never collected
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GenerateConsoleCtrlEvent(uint ev, uint group);
    // Attach to the console of `pid`, ignore the event in this process, raise it for every process on that
    // console (group 0), detach. Returns "ok <utc ticks when raised>" or "error <step> <win32>".
    public static string Send(uint pid, uint ev)
    {
        FreeConsole();
        if (!AttachConsole(pid)) return "error attach " + Marshal.GetLastWin32Error();
        SetConsoleCtrlHandler(IntPtr.Zero, true);      // ignore CTRL_C here
        SetConsoleCtrlHandler(Swallow, true);          // and CTRL_BREAK (the NULL form covers CTRL_C only)
        long t = DateTime.UtcNow.Ticks;
        if (!GenerateConsoleCtrlEvent(ev, 0)) { int e = Marshal.GetLastWin32Error(); FreeConsole(); return "error generate " + e; }
        Thread.Sleep(200);
        FreeConsole();
        return "ok " + t;
    }
}

// Minimal VT screen model for the pseudoconsole output stream (the role pyte plays in tests/g02): conhost's
// renderer only repaints changed cells, so checks read the screen, not the byte stream. Handles printable text
// (East Asian wide characters take two cells), CR/LF/BS/TAB, CSI CUP/HVP/CUU/CUD/CUF/CUB/CHA/VPA/EL/ED/ECH/ICH/
// DCH/IL/DL/SU/SD, SGR (ignored), DEC private modes 1049/47/1047 (alternate buffer) and 25 (cursor), OSC (ignored).
public sealed class X1Screen
{
    int rows, cols, r, c; bool pendingWrap; char[][] main, alt, cur; bool altOn;
    public bool AltActive { get { return altOn; } }
    public bool CursorVisible = true;
    public int AltEnterCount, AltLeaveCount;
    readonly Decoder dec = new UTF8Encoding(false).GetDecoder();
    int state; StringBuilder seq = new StringBuilder();
    public X1Screen(int cols, int rows) { this.cols = cols; this.rows = rows; main = Blank(); alt = Blank(); cur = main; }
    char[][] Blank() { char[][] g = new char[rows][]; for (int i = 0; i < rows; i++) { g[i] = new char[cols]; for (int j = 0; j < cols; j++) g[i][j] = ' '; } return g; }
    public void Resize(int ncols, int nrows)
    {
        char[][] nm = Copy(main, ncols, nrows), na = Copy(alt, ncols, nrows);
        cols = ncols; rows = nrows; main = nm; alt = na; cur = altOn ? alt : main;
        if (r >= rows) r = rows - 1; if (c >= cols) c = cols - 1; pendingWrap = false;
    }
    static char[][] Copy(char[][] g, int ncols, int nrows)
    {
        char[][] n = new char[nrows][];
        for (int i = 0; i < nrows; i++) { n[i] = new char[ncols]; for (int j = 0; j < ncols; j++) n[i][j] = (i < g.Length && j < g[i].Length) ? g[i][j] : ' '; }
        return n;
    }
    static bool Wide(int cp)
    {
        return (cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) || (cp >= 0xAC00 && cp <= 0xD7A3) ||
               (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE4F) || (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6) ||
               (cp >= 0x1F300 && cp <= 0x1F64F) || (cp >= 0x1F900 && cp <= 0x1F9FF) || (cp >= 0x20000 && cp <= 0x3FFFD);
    }
    public void Feed(byte[] data)
    {
        char[] chars = new char[data.Length + 8];
        int n = dec.GetChars(data, 0, data.Length, chars, 0);
        for (int i = 0; i < n; i++)
        {
            char ch = chars[i];
            int cp = ch;
            if (char.IsHighSurrogate(ch) && i + 1 < n && char.IsLowSurrogate(chars[i + 1])) { cp = char.ConvertToUtf32(ch, chars[i + 1]); i++; }
            Step(cp);
        }
    }
    void Step(int cp)
    {
        if (state == 1) // after ESC
        {
            if (cp == '[') { state = 2; seq.Length = 0; return; }
            if (cp == ']') { state = 3; return; }
            if (cp == '(' || cp == ')') { state = 5; return; }
            state = 0; return;
        }
        if (state == 5) { state = 0; return; }
        if (state == 3) { if (cp == 7) state = 0; else if (cp == 27) state = 4; return; }   // OSC
        if (state == 4) { state = 0; return; }                                              // ESC \ ends OSC
        if (state == 2)
        {
            if (cp >= 0x40 && cp <= 0x7E) { Csi(seq.ToString(), (char)cp); state = 0; }
            else seq.Append((char)cp);
            return;
        }
        if (cp == 27) { state = 1; return; }
        if (cp == '\r') { c = 0; pendingWrap = false; return; }
        if (cp == '\n') { LineFeed(); pendingWrap = false; return; }
        if (cp == 8) { if (c > 0) c--; pendingWrap = false; return; }
        if (cp == 9) { c = Math.Min(cols - 1, (c / 8 + 1) * 8); return; }
        if (cp < 32 || cp == 127) return;
        bool wide = Wide(cp);
        if (pendingWrap || (wide && c == cols - 1)) { c = 0; LineFeed(); pendingWrap = false; }
        string s = char.ConvertFromUtf32(cp);
        cur[r][c] = s.Length == 1 ? s[0] : '\uFFFD';   // non-BMP stored as U+FFFD (cell content only)
        if (wide && c + 1 < cols) cur[r][c + 1] = '\0';
        int adv = wide ? 2 : 1;
        if (c + adv >= cols) { c = cols - 1; pendingWrap = true; } else c += adv;
    }
    void LineFeed() { if (r == rows - 1) ScrollUp(1); else r++; }
    void ScrollUp(int n) { for (int k = 0; k < n; k++) { for (int i = 0; i < rows - 1; i++) cur[i] = cur[i + 1]; cur[rows - 1] = BlankRow(); } }
    void ScrollDown(int n) { for (int k = 0; k < n; k++) { for (int i = rows - 1; i > 0; i--) cur[i] = cur[i - 1]; cur[0] = BlankRow(); } }
    char[] BlankRow() { char[] a = new char[cols]; for (int j = 0; j < cols; j++) a[j] = ' '; return a; }
    static int P(string[] ps, int i, int def) { int v; if (i < ps.Length && int.TryParse(ps[i], out v) && v > 0) return v; return def; }
    static int P0(string[] ps, int i) { int v; if (i < ps.Length && int.TryParse(ps[i], out v)) return v; return 0; }
    void Csi(string body, char f)
    {
        bool priv = body.StartsWith("?");
        string[] ps = (priv ? body.Substring(1) : body).Split(';');
        if (priv)
        {
            foreach (string p in ps)
            {
                if (p == "1049" || p == "47" || p == "1047")
                {
                    if (f == 'h' && !altOn) { altOn = true; AltEnterCount++; alt = Blank(); cur = alt; }
                    else if (f == 'l' && altOn) { altOn = false; AltLeaveCount++; cur = main; }
                }
                if (p == "25") CursorVisible = (f == 'h');
            }
            return;
        }
        if ("HfABCDGdJKXL@PM".IndexOf(f) >= 0) pendingWrap = false;   // SGR and other non-moving controls keep it
        switch (f)
        {
            case 'H': case 'f': r = Math.Min(rows, P(ps, 0, 1)) - 1; c = Math.Min(cols, P(ps, 1, 1)) - 1; break;
            case 'A': r = Math.Max(0, r - P(ps, 0, 1)); break;
            case 'B': r = Math.Min(rows - 1, r + P(ps, 0, 1)); break;
            case 'C': c = Math.Min(cols - 1, c + P(ps, 0, 1)); break;
            case 'D': c = Math.Max(0, c - P(ps, 0, 1)); break;
            case 'G': c = Math.Min(cols, P(ps, 0, 1)) - 1; break;
            case 'd': r = Math.Min(rows, P(ps, 0, 1)) - 1; break;
            case 'K': { int m = P0(ps, 0); int a = m == 0 ? c : 0, b = m == 1 ? c : cols - 1; for (int j = a; j <= b && j < cols; j++) cur[r][j] = ' '; break; }
            case 'J':
                {
                    int m = P0(ps, 0);
                    if (m == 2 || m == 3) { for (int i = 0; i < rows; i++) cur[i] = BlankRow(); }
                    else if (m == 0) { for (int j = c; j < cols; j++) cur[r][j] = ' '; for (int i = r + 1; i < rows; i++) cur[i] = BlankRow(); }
                    else { for (int j = 0; j <= c && j < cols; j++) cur[r][j] = ' '; for (int i = 0; i < r; i++) cur[i] = BlankRow(); }
                    break;
                }
            case 'X': { int n = P(ps, 0, 1); for (int j = c; j < c + n && j < cols; j++) cur[r][j] = ' '; break; }
            case '@': { int n = P(ps, 0, 1); for (int j = cols - 1; j >= c + n; j--) cur[r][j] = cur[r][j - n]; for (int j = c; j < c + n && j < cols; j++) cur[r][j] = ' '; break; }
            case 'P': { int n = P(ps, 0, 1); for (int j = c; j < cols; j++) cur[r][j] = j + n < cols ? cur[r][j + n] : ' '; break; }
            case 'L': { int n = P(ps, 0, 1); for (int k = 0; k < n; k++) { for (int i = rows - 1; i > r; i--) cur[i] = cur[i - 1]; cur[r] = BlankRow(); } break; }
            case 'M': { int n = P(ps, 0, 1); for (int k = 0; k < n; k++) { for (int i = r; i < rows - 1; i++) cur[i] = cur[i + 1]; cur[rows - 1] = BlankRow(); } break; }
            case 'S': ScrollUp(P(ps, 0, 1)); break;
            case 'T': ScrollDown(P(ps, 0, 1)); break;
            default: break;   // m (SGR), r, t, n, ...: no effect on the text grid
        }
    }
    public string Text()
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rows; i++)
        {
            StringBuilder line = new StringBuilder();
            foreach (char ch in cur[i]) if (ch != '\0') line.Append(ch);
            sb.Append(line.ToString().TrimEnd()); sb.Append('\n');
        }
        return sb.ToString();
    }
}
