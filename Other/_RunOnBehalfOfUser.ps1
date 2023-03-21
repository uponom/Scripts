<#
   Script executes an app on behalf a logged user.
   It can be useful if you execute e.g. a scheduled task as LOCAL SYSTEM and also you need run something in current logged user context - for example show a message or so.
#>

param(
    $appPath = 'C:\Windows\system32\cmd.exe',   # For example "C:\Windows\System32\notepad.exe"
    $cmdLine = " /k whoami"                     # if not empty, then the first charcter must be a whitespace!
)

#requires -runasadmin

Add-Type -TypeDefinition @"
using System; 
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]

public struct STARTUPINFO {
   public int cb;
   public String lpReserved;
   public String lpDesktop;
   public String lpTitle;
   public uint dwX;
   public uint dwY;
   public uint dwXSize;
   public uint dwYSize;
   public uint dwXCountChars;
   public uint dwYCountChars;
   public uint dwFillAttribute;
   public uint dwFlags;
   public short wShowWindow;
   public short cbReserved2;
   public IntPtr lpReserved2;
   public IntPtr hStdInput;
   public IntPtr hStdOutput;
   public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION {
   public IntPtr hProcess;
   public IntPtr hThread;
   public uint dwProcessId;
   public uint dwThreadId;
}

public static class Kernel32 {
   [DllImport("kernel32.dll")]
   public static extern uint WTSGetActiveConsoleSessionId();

   [DllImport("Wtsapi32.dll")]
   public static extern bool WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public static extern bool DuplicateTokenEx(
       IntPtr ExistingTokenHandle,
       uint dwDesiredAccess,
       IntPtr lpThreadAttributes,
       int TokenType,
       int ImpersonationLevel,
       ref IntPtr DuplicateTokenHandle);

   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public static extern bool CreateProcessAsUser(
       IntPtr hToken,
       String lpApplicationName,
       String lpCommandLine,
       IntPtr lpProcessAttributes,
       IntPtr lpThreadAttributes,
       bool bInheritHandle,
       uint dwCreationFlags,
       IntPtr lpEnvironment,
       String lpCurrentDirectory,
       ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(IntPtr hSnapshot);
}
"@


# $k32 = [kernel32]

$hImpersonationToken = [IntPtr]::Zero
$activeSessionId = [kernel32]::WTSGetActiveConsoleSessionId()
[kernel32]::WTSQueryUserToken($activeSessionId, [ref]$hImpersonationToken) # runs as "local system" only

$hUserToken = [intPtr]::Zero
[kernel32]::DuplicateTokenEx($hImpersonationToken, 0, [IntPtr]::Zero, 2, 1, [ref]$hUserToken);
[kernel32]::CloseHandle($hImpersonationToken)

$startInfo = new-object STARTUPINFO
$procInfo = new-object PROCESS_INFORMATION

$marshal = [System.Runtime.InteropServices.Marshal]
$startInfo.cb = $marshal::SizeOf($startInfo)
$startInfo.lpDesktop = "winsta0\default"
 
$hidden = $false
if ($hidden) {
   $startInfo.dwFlags = 1
   $startInfo.wShowWindow = 0
   $dwCreationFlags = 0x08000400
} else {
   $startInfo.wShowWindow = 5
   $dwCreationFlags = 0x00000410
}

$dir    = [System.IO.Directory]::GetParent($appPath).Fullname
[kernel32]::CreateProcessAsUser($hUserToken, $appPath, $cmdLine, 0, 0, $false, $dwCreationFlags, 0, $dir, [ref]$startInfo, [ref]$procInfo)
$result = $marshal::GetLastWin32Error()
$id    = $procInfo.dwProcessId

[kernel32]::CloseHandle($hUserToken)
if ($pEnv -ne [IntPtr].Zero) {[kernel32]::DestroyEnvironmentBlock($pEnv)}
[kernel32]::CloseHandle($procInfo.hThread)
[kernel32]::CloseHandle($procInfo.hProcess)
