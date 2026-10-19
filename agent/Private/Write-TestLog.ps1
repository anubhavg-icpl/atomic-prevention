function Write-TestLog {
    <#
    .SYNOPSIS
        Writes a structured log entry for a test result.

    .DESCRIPTION
        Appends a timestamped, structured log entry to the Atomic Prevention
        log file. Each execution run creates or appends to a log file in
        the specified output directory.

    .PARAMETER LogPath
        Full path to the log file.

    .PARAMETER TestName
        Display name of the test.

    .PARAMETER TechniqueId
        MITRE ATT&CK technique ID (e.g. T1059.001).

    .PARAMETER Verdict
        The execution verdict: blocked, allowed, or error.

    .PARAMETER Reason
        Human-readable explanation of the verdict.

    .PARAMETER ExecutionTimeMs
        How long the test took in milliseconds.

    .PARAMETER ExitCode
        Process exit code, if available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory)]
        [string]$TestName,

        [Parameter()]
        [string]$TechniqueId = '',

        [Parameter(Mandatory)]
        [ValidateSet('blocked', 'allowed', 'error')]
        [string]$Verdict,

        [Parameter()]
        [string]$Reason = '',

        [Parameter()]
        [int]$ExecutionTimeMs = 0,

        [Parameter()]
        [AllowNull()]
        [Nullable[int]]$ExitCode
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $verdictUpper = $Verdict.ToUpper()
    $exitCodeStr = if ($null -ne $ExitCode) { $ExitCode.ToString() } else { 'N/A' }

    $logLine = "[$timestamp] [$verdictUpper] $TechniqueId | $TestName | ExitCode=$exitCodeStr | ${ExecutionTimeMs}ms | $Reason"

    # Ensure the directory exists
    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    Add-Content -Path $LogPath -Value $logLine -Encoding UTF8
}
