function Send-Results {
    <#
    .SYNOPSIS
        Uploads test results to the Atomic Prevention backend.

    .DESCRIPTION
        Sends the collected test results to the Atomic Prevention server API
        via the /api/results/submit endpoint. The payload matches the
        SubmitResultsRequest schema expected by the backend.

        If the upload fails, the function writes a warning but does not
        throw, since results are always saved locally as a fallback.

    .PARAMETER ServerUrl
        Base URL of the Atomic Prevention server (e.g. http://localhost:3000).

    .PARAMETER PlaybookId
        UUID of the playbook that was executed.

    .PARAMETER Results
        Array of result hashtables from Test-Prevention.

    .PARAMETER ResultsEndpoint
        API path for result submission. Defaults to /api/results/submit.

    .OUTPUTS
        A hashtable with keys: Success (bool), RunId (string or null),
        Summary (hashtable or null), Error (string or null).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ServerUrl,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PlaybookId,

        [Parameter(Mandatory)]
        [object[]]$Results,

        [Parameter()]
        [string]$ResultsEndpoint = '/api/results/submit'
    )

    $response = @{
        Success = $false
        RunId   = $null
        Summary = $null
        Error   = $null
    }

    # Build the request body matching SubmitResultsRequest
    $hostname = try { [System.Net.Dns]::GetHostName() } catch { $env:COMPUTERNAME }

    $resultPayloads = @()
    foreach ($r in $Results) {
        # Skip tests that were not actually executed (e.g. dry-run)
        if ($r.Verdict -eq 'skipped') { continue }

        $resultPayloads += @{
            test_id           = $r.TestId
            verdict           = $r.Verdict
            exit_code         = $r.ExitCode
            error_message     = $r.ErrorMessage
            execution_time_ms = $r.ExecutionTimeMs
        }
    }

    if ($resultPayloads.Count -eq 0) {
        $response.Error = 'No results to submit (all tests were skipped)'
        Write-Warning $response.Error
        return $response
    }

    $body = @{
        playbook_id = $PlaybookId
        hostname    = $hostname
        results     = $resultPayloads
    } | ConvertTo-Json -Depth 10

    $uri = "$($ServerUrl.TrimEnd('/'))$ResultsEndpoint"

    Write-Host "`n  Uploading results to $uri ..." -ForegroundColor Cyan

    try {
        $webResponse = Invoke-RestMethod `
            -Uri $uri `
            -Method Post `
            -ContentType 'application/json' `
            -Body $body `
            -TimeoutSec 30 `
            -ErrorAction Stop

        $response.Success = $true
        $response.RunId   = $webResponse.run_id
        $response.Summary = $webResponse.summary

        Write-Host "  Upload successful. Run ID: $($response.RunId)" -ForegroundColor Green

        if ($response.Summary) {
            Write-Host "  Server summary -- Blocked: $($response.Summary.blocked), Allowed: $($response.Summary.allowed), Error: $($response.Summary.error)" -ForegroundColor Cyan
        }
    }
    catch {
        $response.Error = $_.Exception.Message
        Write-Warning "Failed to upload results: $($response.Error)"
        Write-Warning 'Results are saved locally. You can retry upload later or submit manually.'
    }

    return $response
}
