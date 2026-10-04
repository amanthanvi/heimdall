<#
.SYNOPSIS
  G03 instrumented SSH agent on a named pipe (harness fixture, not product code).

.DESCRIPTION
  Serves the SSH agent protocol (draft-ietf-sshm-ssh-agent: REQUEST_IDENTITIES,
  SIGN_REQUEST; everything else is refused) on \\.\pipe\<PipeName>, using
  ephemeral ECDSA P-256 keys generated in memory at start. Private keys never
  leave this process and are never written to disk. Every connection and
  request is logged as JSON lines (message type, key fingerprint, client PID,
  client image name, client SID via ImpersonateNamedPipeClient), so probes can
  observe exactly which endpoint a client selected.

  Windows: the pipe is created directly with CreateNamedPipeW (P/Invoke) so
  every property the N2 design names is explicit and identical under Windows
  PowerShell 5.1 and PowerShell 7 (.NET's NamedPipeServerStream cannot set
  PIPE_REJECT_REMOTE_CLIENTS: its pipe mode carries only the transmission
  mode, and it adds FILE_FLAG_FIRST_PIPE_INSTANCE whenever max instances is 1;
  dotnet/runtime NamedPipeServerStream.Windows.cs [G03-S21]):
    * DACL from SDDL, protected:
        OwnerOnly                        D:P(A;;GA;;;<owner SID>)
        AuthenticatedUsers               + (A;;0x12019b;;;AU)  connect/read/write, NO
                                           FILE_CREATE_PIPE_INSTANCE (the mask the
                                           Win32-OpenSSH agent grants AU, agent.c [G03-S02])
        AuthenticatedUsersCreateInstance + (A;;0x12019f;;;AU)  same plus
                                           FILE_CREATE_PIPE_INSTANCE (0x4); test control only
    * PIPE_REJECT_REMOTE_CLIENTS (CreateNamedPipe docs [G03-S10]);
    * nMaxInstances = -MaxInstances (default 1);
    * FILE_FLAG_FIRST_PIPE_INSTANCE unless -NoFirstInstanceFlag, so a
      pre-existing (squatted) pipe of the same name makes startup fail
      (ERROR_ACCESS_DENIED) instead of silently sharing the name.
  Per the CreateNamedPipe docs [G03-S10], instance creation on an existing
  name ALSO fails with ERROR_ACCESS_DENIED when the pipe type, access, instance
  count or time-out differ, or when FIRST_PIPE_INSTANCE is set; probes that
  attribute a denial to the DACL therefore need a same-parameter control.

  Instance lifetime: the ONE server instance is created once and re-armed
  after every client with NamedPipeServerStream.Disconnect()
  (DisconnectNamedPipe on Windows), then WaitForConnectionAsync again; .NET
  allows Disconnect from the Connected and Broken states and a new wait from
  Disconnected (NamedPipeServerStream.cs / .Windows.cs / .Unix.cs [G03-S21]).
  The pipe name therefore never has zero instances while the agent runs, so
  another process's transient instance (e.g. P-W05's TryCreateInstance) can
  neither win a recreate race nor make the agent exit. Only if Disconnect
  throws does the agent fall back to dispose + recreate (logged as
  'rearm' method 'recreate'; a recreate failure exits 4).

  Non-Windows (harness self-test only): .NET maps the pipe to a Unix-domain
  socket; DACL and client-identity features are skipped.

  Compatible with Windows PowerShell 5.1 and PowerShell 7.x.
#>
param(
    [Parameter(Mandatory = $true)][string]$PipeName,
    [Parameter(Mandatory = $true)][string]$LogPath,
    [string]$ReadyFile,
    [string]$PublicKeyDir,
    [ValidateRange(1, 4)][int]$KeyCount = 1,
    [string]$AllowedKeyIndexes,          # comma-separated 1-based indexes; default: all
    [ValidateRange(1, 86400)][int]$RunSeconds = 300,
    [ValidateSet('OwnerOnly', 'AuthenticatedUsers', 'AuthenticatedUsersCreateInstance')][string]$Access = 'OwnerOnly',
    [ValidateRange(1, 255)][int]$MaxInstances = 1,
    [switch]$NoFirstInstanceFlag,
    [switch]$RefuseSign,
    [int]$MaxMessageBytes = 262144,
    [int]$ClientIdleTimeoutMs = 15000
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$OnWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$Utf8 = New-Object System.Text.UTF8Encoding($false)

$MsgNames = @{
    1 = 'SSH_AGENTC_REQUEST_RSA_IDENTITIES'; 5 = 'SSH_AGENT_FAILURE'; 6 = 'SSH_AGENT_SUCCESS'
    11 = 'SSH2_AGENTC_REQUEST_IDENTITIES'; 13 = 'SSH2_AGENTC_SIGN_REQUEST'
    17 = 'SSH2_AGENTC_ADD_IDENTITY'; 18 = 'SSH2_AGENTC_REMOVE_IDENTITY'; 19 = 'SSH2_AGENTC_REMOVE_ALL_IDENTITIES'
    20 = 'SSH_AGENTC_ADD_SMARTCARD_KEY'; 21 = 'SSH_AGENTC_REMOVE_SMARTCARD_KEY'
    22 = 'SSH_AGENTC_LOCK'; 23 = 'SSH_AGENTC_UNLOCK'; 25 = 'SSH2_AGENTC_ADD_ID_CONSTRAINED'
    26 = 'SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED'; 27 = 'SSH_AGENTC_EXTENSION'
}

function Write-AgentLog {
    param([hashtable]$Entry)
    $Entry['ts'] = [DateTime]::UtcNow.ToString('o')
    $Entry['agent_pid'] = $PID
    $Entry['pipe'] = $PipeName
    $line = (New-Object PSObject -Property $Entry) | ConvertTo-Json -Compress -Depth 5
    [System.IO.File]::AppendAllText($LogPath, $line + "`n", $Utf8)
}

# ---------------------------------------------------------------- wire helpers
function Add-U32 { param([System.IO.MemoryStream]$Ms, [uint32]$V)
    $b = [BitConverter]::GetBytes($V); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }; $Ms.Write($b, 0, 4) }
function Add-SshString { param([System.IO.MemoryStream]$Ms, [byte[]]$Data)
    if ($null -eq $Data) { $Data = New-Object byte[] 0 }
    Add-U32 -Ms $Ms -V ([uint32]$Data.Length); if ($Data.Length -gt 0) { $Ms.Write($Data, 0, $Data.Length) } }
function Get-U32 { param([byte[]]$Buf, [int]$Off)
    if ($Off + 4 -gt $Buf.Length) { throw 'truncated u32' }
    return [uint32](([uint32]$Buf[$Off] -shl 24) -bor ([uint32]$Buf[$Off + 1] -shl 16) -bor ([uint32]$Buf[$Off + 2] -shl 8) -bor [uint32]$Buf[$Off + 3]) }
function Get-SshString { param([byte[]]$Buf, [int]$Off)
    $len = Get-U32 -Buf $Buf -Off $Off
    if ($len -gt ($Buf.Length - $Off - 4)) { throw 'truncated string' }
    $out = New-Object byte[] $len
    if ($len -gt 0) { [Array]::Copy($Buf, $Off + 4, $out, 0, $len) }
    return , @($out, ($Off + 4 + [int]$len)) }
function ConvertTo-Mpint { param([byte[]]$Unsigned)
    $i = 0; while ($i -lt $Unsigned.Length -and $Unsigned[$i] -eq 0) { $i++ }
    $len = $Unsigned.Length - $i
    if ($len -eq 0) { return (New-Object byte[] 0) }
    $pad = 0; if ($Unsigned[$i] -ge 0x80) { $pad = 1 }
    $out = New-Object byte[] ($len + $pad)
    [Array]::Copy($Unsigned, $i, $out, $pad, $len)
    return , $out }
function Get-Fingerprint { param([byte[]]$Blob)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return 'SHA256:' + ([Convert]::ToBase64String($sha.ComputeHash($Blob))).TrimEnd('=') } finally { $sha.Dispose() } }
function Test-BytesEqual { param([byte[]]$A, [byte[]]$B)
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
    return $true }

# ---------------------------------------------------------------- keys
$KeyType = [System.Text.Encoding]::ASCII.GetBytes('ecdsa-sha2-nistp256')
$CurveId = [System.Text.Encoding]::ASCII.GetBytes('nistp256')
$Keys = New-Object System.Collections.ArrayList
$allowed = @()
if ($AllowedKeyIndexes) { $allowed = @($AllowedKeyIndexes -split ',' | ForEach-Object { [int]$_.Trim() }) }
for ($k = 1; $k -le $KeyCount; $k++) {
    $ec = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $prm = $ec.ExportParameters($false)
    $q = New-Object byte[] 65
    $q[0] = 4; [Array]::Copy($prm.Q.X, 0, $q, 1, 32); [Array]::Copy($prm.Q.Y, 0, $q, 33, 32)
    $ms = New-Object System.IO.MemoryStream
    Add-SshString -Ms $ms -Data $KeyType; Add-SshString -Ms $ms -Data $CurveId; Add-SshString -Ms $ms -Data $q
    $blob = $ms.ToArray()
    $comment = "heimdall-g03-probe-$k"
    $isAllowed = ($allowed.Count -eq 0) -or ($allowed -contains $k)
    [void]$Keys.Add([pscustomobject]@{ Index = $k; Ec = $ec; Blob = $blob; Fingerprint = (Get-Fingerprint $blob); Comment = $comment; Allowed = $isAllowed
            AuthorizedKey = ('ecdsa-sha2-nistp256 ' + [Convert]::ToBase64String($blob) + ' ' + $comment) })
}
if ($PublicKeyDir) {
    if (-not (Test-Path -LiteralPath $PublicKeyDir)) { New-Item -ItemType Directory -Force -Path $PublicKeyDir | Out-Null }
    foreach ($key in $Keys) {
        [System.IO.File]::WriteAllText((Join-Path $PublicKeyDir ("probe-key-{0}.pub" -f $key.Index)), $key.AuthorizedKey + "`n", $Utf8)
    }
}

function New-SignatureBlob { param($Key, [byte[]]$Data)
    $sig = $Key.Ec.SignData($Data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)   # IEEE P1363 r||s
    if ($sig.Length -ne 64) { throw "unexpected ECDSA signature length $($sig.Length)" }
    $r = New-Object byte[] 32; $s = New-Object byte[] 32
    [Array]::Copy($sig, 0, $r, 0, 32); [Array]::Copy($sig, 32, $s, 0, 32)
    $inner = New-Object System.IO.MemoryStream
    Add-SshString -Ms $inner -Data (ConvertTo-Mpint $r); Add-SshString -Ms $inner -Data (ConvertTo-Mpint $s)
    $outer = New-Object System.IO.MemoryStream
    Add-SshString -Ms $outer -Data $KeyType; Add-SshString -Ms $outer -Data $inner.ToArray()
    return , $outer.ToArray() }

# ---------------------------------------------------------------- client identity (Windows)
if ($OnWindows) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class G03PipeInfo {
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool ConvertSidToStringSidW(IntPtr Sid, out IntPtr StringSid);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr hMem);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public static uint ClientPid(IntPtr h) { uint pid; return GetNamedPipeClientProcessId(h, out pid) ? pid : 0u; }
  public static string ClientSid(IntPtr h) {
    if (!ImpersonateNamedPipeClient(h)) return "error:impersonate:" + Marshal.GetLastWin32Error();
    IntPtr tok = IntPtr.Zero;
    try {
      if (!OpenThreadToken(GetCurrentThread(), 0x0008, true, out tok)) return "error:openthreadtoken:" + Marshal.GetLastWin32Error();
      int len; GetTokenInformation(tok, 1, IntPtr.Zero, 0, out len);
      if (len <= 0) return "error:tokenlen";
      IntPtr buf = Marshal.AllocHGlobal(len);
      try {
        if (!GetTokenInformation(tok, 1, buf, len, out len)) return "error:gettokeninfo:" + Marshal.GetLastWin32Error();
        IntPtr sid = Marshal.ReadIntPtr(buf); IntPtr str;
        if (!ConvertSidToStringSidW(sid, out str)) return "error:convertsid";
        try { return Marshal.PtrToStringUni(str); } finally { LocalFree(str); }
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { if (tok != IntPtr.Zero) CloseHandle(tok); RevertToSelf(); }
  }
}
public static class G03PipeCreate {
  [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateNamedPipeW(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, ref SECURITY_ATTRIBUTES sa);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out uint size);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr hMem);
  public const uint PIPE_ACCESS_DUPLEX = 0x3, FILE_FLAG_OVERLAPPED = 0x40000000, FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
  public const uint PIPE_TYPE_BYTE = 0x0, PIPE_READMODE_BYTE = 0x0, PIPE_WAIT = 0x0, PIPE_REJECT_REMOTE_CLIENTS = 0x8;
  // Returns the raw handle (INVALID_HANDLE_VALUE = -1 on failure) and the Win32 error.
  public static IntPtr Create(string name, string sddl, uint maxInstances, bool firstInstance, bool rejectRemote, out int error) {
    IntPtr sd; uint size; error = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { error = Marshal.GetLastWin32Error(); return new IntPtr(-1); }
    try {
      SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES(); sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)); sa.lpSecurityDescriptor = sd; sa.bInheritHandle = 0;
      uint open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0u);
      uint mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | (rejectRemote ? PIPE_REJECT_REMOTE_CLIENTS : 0u);
      IntPtr h = CreateNamedPipeW("\\\\.\\pipe\\" + name, open, mode, maxInstances, 65536, 65536, 0, ref sa);
      if (h == new IntPtr(-1)) error = Marshal.GetLastWin32Error();
      return h;
    } finally { LocalFree(sd); }
  }
}
'@
}

# ---------------------------------------------------------------- server
$EndpointPath = $null
if ($OnWindows) { $EndpointPath = "\\.\pipe\$PipeName" }
elseif ([System.IO.Path]::IsPathRooted($PipeName)) { $EndpointPath = $PipeName }
else { $EndpointPath = Join-Path ([System.IO.Path]::GetTempPath()) ("CoreFxPipe_" + $PipeName) }

$Sddl = $null
$FirstInstance = -not $NoFirstInstanceFlag
$RejectRemote = $true
if ($OnWindows) {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $Sddl = "D:P(A;;GA;;;$me)"
    if ($Access -eq 'AuthenticatedUsers') { $Sddl += '(A;;0x12019b;;;AU)' }
    elseif ($Access -eq 'AuthenticatedUsersCreateInstance') { $Sddl += '(A;;0x12019f;;;AU)' }
}

function New-AgentServer {
    if ($OnWindows) {
        $err = 0
        $raw = [G03PipeCreate]::Create($PipeName, $Sddl, [uint32]$MaxInstances, $FirstInstance, $RejectRemote, [ref]$err)
        if ($raw -eq [IntPtr](-1)) {
            $ex = New-Object System.ComponentModel.Win32Exception($err)
            throw (New-Object System.IO.IOException(("CreateNamedPipeW failed: win32_error={0} ({1})" -f $err, $ex.Message), $ex))
        }
        $safe = New-Object Microsoft.Win32.SafeHandles.SafePipeHandle($raw, $true)
        # isAsync = $true matches FILE_FLAG_OVERLAPPED; isConnected = $false.
        return New-Object System.IO.Pipes.NamedPipeServerStream([System.IO.Pipes.PipeDirection]::InOut, $true, $false, $safe)
    }
    return New-Object System.IO.Pipes.NamedPipeServerStream($PipeName, [System.IO.Pipes.PipeDirection]::InOut, $MaxInstances, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)
}

function Get-InnerException { param($E) $x = $E; while ($x.InnerException) { $x = $x.InnerException }; return $x }

function Read-Exact { param([System.IO.Stream]$S, [int]$N, [int]$TimeoutMs)
    $buf = New-Object byte[] $N; $got = 0
    while ($got -lt $N) {
        $t = $S.ReadAsync($buf, $got, $N - $got)
        if (-not $t.Wait($TimeoutMs)) { return $null }
        if ($t.Result -le 0) { return $null }
        $got += $t.Result
    }
    return , $buf }

function Write-Message { param([System.IO.Stream]$S, [byte[]]$Payload)
    $ms = New-Object System.IO.MemoryStream
    Add-U32 -Ms $ms -V ([uint32]$Payload.Length); $ms.Write($Payload, 0, $Payload.Length)
    $b = $ms.ToArray(); $S.Write($b, 0, $b.Length); $S.Flush() }

function Invoke-Request { param([byte[]]$Body, [hashtable]$Conn)
    $type = [int]$Body[0]
    $entry = @{ event = 'request'; conn = $Conn.Id; msg_type = $type; msg_name = $MsgNames[$type]; length = $Body.Length }
    $resp = New-Object System.IO.MemoryStream
    $result = 'failure'
    try {
        switch ($type) {
            11 {
                $list = @($Keys | Where-Object { $_.Allowed })
                $resp.WriteByte(12); Add-U32 -Ms $resp -V ([uint32]$list.Count)
                foreach ($key in $list) { Add-SshString -Ms $resp -Data $key.Blob; Add-SshString -Ms $resp -Data ([System.Text.Encoding]::UTF8.GetBytes($key.Comment)) }
                $result = "identities:$($list.Count)"
            }
            13 {
                $r1 = Get-SshString -Buf $Body -Off 1; $blob = $r1[0]
                $r2 = Get-SshString -Buf $Body -Off $r1[1]; $data = $r2[0]
                $flags = 0; if ($r2[1] + 4 -le $Body.Length) { $flags = Get-U32 -Buf $Body -Off $r2[1] }
                $entry['key_fp'] = Get-Fingerprint $blob; $entry['data_len'] = $data.Length; $entry['flags'] = $flags
                $key = $null; foreach ($cand in $Keys) { if (Test-BytesEqual $cand.Blob $blob) { $key = $cand } }
                if ($null -eq $key) { $resp.WriteByte(5); $result = 'denied_unknown_key' }
                elseif (-not $key.Allowed) { $resp.WriteByte(5); $result = 'denied_filtered_key' }
                elseif ($RefuseSign) { $resp.WriteByte(5); $result = 'denied_refuse_sign' }
                else { $sig = New-SignatureBlob -Key $key -Data $data; $resp.WriteByte(14); Add-SshString -Ms $resp -Data $sig; $result = 'signed' }
            }
            27 {
                try { $r1 = Get-SshString -Buf $Body -Off 1; $entry['extension'] = [System.Text.Encoding]::ASCII.GetString($r1[0]) } catch { $entry['extension'] = '<unparseable>' }
                $resp.WriteByte(5); $result = 'denied_extension'
            }
            default { $resp.WriteByte(5); $result = 'denied_unsupported' }
        }
    } catch {
        $resp = New-Object System.IO.MemoryStream; $resp.WriteByte(5); $result = 'error_malformed'
        $entry['detail'] = $_.Exception.Message
    }
    Write-AgentLog $entry
    Write-AgentLog @{ event = 'response'; conn = $Conn.Id; msg_type = $type; result = $result }
    return , $resp.ToArray() }

function Write-Ready { param([string]$Status, [string]$Detail)
    if (-not $ReadyFile) { return }
    $o = [ordered]@{ status = $Status; detail = $Detail; pipe = $PipeName; endpoint_path = $EndpointPath; agent_pid = $PID
        access = $Access; sddl = $Sddl; max_instances = $MaxInstances
        first_instance_flag = ($OnWindows -and $FirstInstance); reject_remote_clients = ($OnWindows -and $RejectRemote)
        started_at = [DateTime]::UtcNow.ToString('o')
        keys = @($Keys | ForEach-Object { [ordered]@{ index = $_.Index; fingerprint = $_.Fingerprint; allowed = $_.Allowed; comment = $_.Comment } }) }
    [System.IO.File]::WriteAllText($ReadyFile, (($o | ConvertTo-Json -Depth 5) + "`n"), $Utf8) }

$deadline = [DateTime]::UtcNow.AddSeconds($RunSeconds)
$server = $null
try { $server = New-AgentServer }
catch {
    $ie = Get-InnerException $_.Exception
    Write-AgentLog @{ event = 'error'; detail = ('create_failed: ' + $ie.GetType().Name + ': ' + $ie.Message); hresult = $ie.HResult }
    Write-Ready -Status 'create_failed' -Detail ($ie.GetType().Name + ': ' + $ie.Message)
    exit 3
}
Write-AgentLog @{ event = 'listening'; endpoint = $EndpointPath; access = $Access; keys = @($Keys | ForEach-Object { $_.Fingerprint }) }
Write-Ready -Status 'listening' -Detail ''

$connId = 0
$exitCode = 0
try {
    while ([DateTime]::UtcNow -lt $deadline) {
        $wait = $server.WaitForConnectionAsync()
        $connected = $false
        while ([DateTime]::UtcNow -lt $deadline) { if ($wait.Wait(500)) { $connected = $true; break } }
        if (-not $connected) { break }
        $connId++
        $conn = @{ Id = $connId }
        $connectEntry = @{ event = 'connect'; conn = $connId }
        if ($OnWindows) {
            $h = $server.SafePipeHandle.DangerousGetHandle()
            $cpid = [G03PipeInfo]::ClientPid($h)
            $connectEntry['client_pid'] = $cpid
            try {
                $cp = Get-Process -Id $cpid -ErrorAction Stop
                $connectEntry['client_image'] = $cp.ProcessName
                # Executable path distinguishes System32 ssh.exe from Git's bundled ssh.exe.
                try { $connectEntry['client_path'] = $cp.Path } catch { $connectEntry['client_path'] = $null }
            } catch { $connectEntry['client_image'] = $null }
        }
        $first = $true
        while ($true) {
            $hdr = Read-Exact -S $server -N 4 -TimeoutMs $ClientIdleTimeoutMs
            if ($null -eq $hdr) { break }
            $len = Get-U32 -Buf $hdr -Off 0
            if ($len -eq 0 -or $len -gt $MaxMessageBytes) { Write-AgentLog @{ event = 'error'; conn = $connId; detail = "bad_length:$len" }; break }
            $body = Read-Exact -S $server -N ([int]$len) -TimeoutMs $ClientIdleTimeoutMs
            if ($null -eq $body) { Write-AgentLog @{ event = 'error'; conn = $connId; detail = 'truncated_body' }; break }
            if ($first) {
                if ($OnWindows) { $connectEntry['client_sid'] = [G03PipeInfo]::ClientSid($server.SafePipeHandle.DangerousGetHandle()) }
                Write-AgentLog $connectEntry; $first = $false
            }
            $reply = Invoke-Request -Body $body -Conn $conn
            Write-Message -S $server -Payload $reply
        }
        if ($first) { Write-AgentLog $connectEntry }
        Write-AgentLog @{ event = 'disconnect'; conn = $connId }
        # Re-arm the SAME instance (no zero-instance window on the name; see header).
        $rearmed = $false
        try { $server.Disconnect(); $rearmed = $true; Write-AgentLog @{ event = 'rearm'; conn = $connId; method = 'disconnect' } }
        catch {
            $ie = Get-InnerException $_.Exception
            Write-AgentLog @{ event = 'rearm'; conn = $connId; method = 'disconnect_failed'; detail = ($ie.GetType().Name + ': ' + $ie.Message) }
        }
        if (-not $rearmed) {
            try { $server.Dispose() } catch { }
            $server = $null
            try { $server = New-AgentServer; Write-AgentLog @{ event = 'rearm'; conn = $connId; method = 'recreate' } }
            catch {
                $ie = Get-InnerException $_.Exception
                Write-AgentLog @{ event = 'error'; detail = ('recreate_failed_possible_squat: ' + $ie.GetType().Name + ': ' + $ie.Message); hresult = $ie.HResult }
                $exitCode = 4
                break
            }
        }
    }
} finally {
    if ($server) { try { $server.Dispose() } catch { } }
    Write-AgentLog @{ event = 'exit'; exit_code = $exitCode; connections = $connId }
    foreach ($key in $Keys) { try { $key.Ec.Dispose() } catch { } }
}
exit $exitCode
