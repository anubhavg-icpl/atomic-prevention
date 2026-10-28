function Get-UecSensorLogs {
    <#
    .SYNOPSIS
        Collects a bounded and redacted tail of local UEC sensor logs.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param()

    $logs = [System.Collections.Generic.List[hashtable]]::new()
    $lineLimit = 200
    try {
        $requestedLines = [int]$env:UEC_SENSOR_LOG_LINES
        if ($requestedLines -ge 0 -and $requestedLines -le 2000) {
            $lineLimit = $requestedLines
        }
    }
    catch {}

    $paths = @()
    $override = [string]$env:UEC_SENSOR_LOG_PATH
    if (-not [string]::IsNullOrWhiteSpace($override)) {
        $paths = @($override -split [System.IO.Path]::PathSeparator | Where-Object { $_ })
    }
    else {
        $isWindows = ($env:OS -eq 'Windows_NT')
        if ($isWindows) {
            $programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
            $roots = @(
                (Join-Path $programData 'UEC\Sensor\Logs'),
                (Join-Path $programData 'UEC Sensor\Logs'),
                (Join-Path $programData 'Infopercept\UecSensor\logs')
            )
            foreach ($root in $roots) {
                if (Test-Path $root) {
                    $paths += @(Get-ChildItem $root -Filter '*.log' -Recurse -ErrorAction SilentlyContinue |
                        Select-Object -First 40 -ExpandProperty FullName)
                }
            }
        }
        elseif ($IsMacOS) {
            if (Test-Path '/Library/Logs/UECSensor') {
                $paths += @(Get-ChildItem '/Library/Logs/UECSensor' -Filter '*.log' -ErrorAction SilentlyContinue |
                    Select-Object -First 40 -ExpandProperty FullName)
            }
        }
        elseif ($IsLinux) {
            if (Test-Path '/var/log/uec-sensor') {
                $paths += @(Get-ChildItem '/var/log/uec-sensor' -Filter '*.log' -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 40 -ExpandProperty FullName)
            }
        }
    }

    $totalBytes = 0
    foreach ($path in $paths) {
        try {
            if (-not (Test-Path $path -PathType Leaf) -or $lineLimit -eq 0) { continue }
            $item = Get-Item $path
            $byteLimit = [Math]::Min(131072, [Math]::Max(1, $lineLimit * 4096))
            $readLength = [int][Math]::Min($item.Length, $byteLimit)
            $stream = [System.IO.File]::OpenRead($path)
            try {
                if ($item.Length -gt $readLength) {
                    $null = $stream.Seek(-$readLength, [System.IO.SeekOrigin]::End)
                }
                $bytes = [byte[]]::new($readLength)
                $null = $stream.Read($bytes, 0, $readLength)
            }
            finally {
                $stream.Dispose()
            }

            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            $lines = @($text -split "`r?`n" | Select-Object -Last $lineLimit)
            $remaining = 131072 - $totalBytes
            if ($remaining -le 0) { break }

            $boundedLines = [System.Collections.Generic.List[string]]::new()
            foreach ($line in $lines) {
                if ($line.Length -gt $remaining) {
                    $boundedLines.Add((Get-RedactedText $line $remaining))
                    $totalBytes = 131072
                    break
                }
                $boundedLines.Add((Get-RedactedText $line))
                $remaining -= [System.Text.Encoding]::UTF8.GetByteCount($line)
                $totalBytes += [System.Text.Encoding]::UTF8.GetByteCount($line)
            }
            $logs.Add(@{
                source = 'uec-sensor'
                path = [string]$path
                lines = @($boundedLines)
            })
            if ($totalBytes -ge 131072) { break }
        }
        catch {
            $logs.Add(@{
                source = 'uec-sensor'
                path = [string]$path
                error = "$($_.Exception.GetType().Name): unable to read log"
            })
        }
    }

    return $logs
}
