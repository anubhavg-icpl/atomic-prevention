function New-DebugLogs {
    <#
    .SYNOPSIS
        Builds bounded run diagnostics from test results.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [object[]]$Results,

        [Parameter(Mandatory)]
        [object[]]$Tests
    )

    $logs = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($result in $Results) {
        $test = @($Tests | Where-Object { $_.id -eq $result.TestId } | Select-Object -First 1)
        $command = if ($test.Count -gt 0) { $test[0].command } else { '' }
        $executor = if ($test.Count -gt 0) { $test[0].executor } else { '' }
        $level = if ($result.Verdict -in @('blocked', 'detected', 'allowed')) { 'info' } else { 'error' }
        $logs.Add(@{
            timestamp = $result.StartedAt
            level = $level
            test_id = $result.TestId
            technique_id = $result.TechniqueId
            command = Get-RedactedText $command 2000
            executor = $executor
            verdict = $result.Verdict
            exit_code = $result.ExitCode
            stdout = Get-RedactedText $result.StdOut 4000
            stderr = Get-RedactedText $result.StdErr 4000
            agent_log_count = @($result.AgentLogs).Count
        })
    }
    return $logs
}
