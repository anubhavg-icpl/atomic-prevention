function Get-ExecutionVerdict {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [bool]$ProcessStarted,

        [AllowNull()]
        [Nullable[int]]$ExitCode,

        [bool]$TimedOut = $false,

        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [string]$StdOut = '',

        [string]$StdErr = ''
    )

    $startupReason = if ($ErrorRecord) { $ErrorRecord.Exception.Message } else { 'Process failed to start' }
    $evidence = "$startupReason`n$StdErr`n$StdOut"
    $blockIndicators = @(
        'Access is denied',
        'blocked by policy',
        'was blocked',
        'BLOCKED:',
        'This script contains malicious content',
        'not allowed to run',
        'AppLocker',
        'Code Integrity',
        'ConstrainedLanguage',
        'quarantined'
    )
    $blockIndicator = $blockIndicators | Where-Object { $evidence -like "*$_*" } | Select-Object -First 1
    $detectIndicator = $null
    $detectMatch = [regex]::Match(
        $evidence,
        '(?i)(?<!not )\bdetected\b|(?<!no )\bdetection\b|(?<!not )\balerted\b|\balert triggered\b|(?<!not )\bsuspicious\b|\bthreat found\b|\bsigma match\b|\bpolicy audit\b|\baudit event\b'
    )
    if ($detectMatch.Success) { $detectIndicator = $detectMatch.Value }

    if (-not $ProcessStarted) {
        if ($blockIndicator) {
            return @{ Verdict = 'blocked'; Reason = "Security control prevented execution: $startupReason" }
        }
        if ($detectIndicator) {
            return @{ Verdict = 'detected'; Reason = "Detection indicator observed without a block (${detectIndicator}): $startupReason" }
        }
        return @{ Verdict = 'error'; Reason = "Process failed to start: $startupReason" }
    }

    if ($TimedOut) {
        return @{ Verdict = 'allowed'; Reason = 'Process ran until the test timeout (not prevented from starting)' }
    }

    if ($blockIndicator) {
        return @{ Verdict = 'blocked'; Reason = "Security control evidence observed: $blockIndicator" }
    }

    if ($detectIndicator) {
        return @{ Verdict = 'detected'; Reason = "Detection indicator observed without a block: $detectIndicator" }
    }

    if ($null -eq $ExitCode) {
        return @{ Verdict = 'error'; Reason = 'Process started but exit code could not be determined' }
    }

    if ($ExitCode -eq 0) {
        return @{ Verdict = 'allowed'; Reason = 'Test command completed successfully' }
    }

    return @{
        Verdict = 'error'
        Reason = "Test command failed with exit code $ExitCode without prevention evidence"
    }
}
