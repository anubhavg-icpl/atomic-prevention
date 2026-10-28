function Get-RedactedText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object]$Value,

        [ValidateRange(1, 16000)]
        [int]$MaxChars = 4000
    )

    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    $patterns = @(
        '(?i)(x-api-key\s*[:=]\s*)\S+',
        '(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)\S+',
        '(?i)((?:password|passwd|secret|token|api[_-]?key)"?\s*[:=]\s*)("[^"\r\n]*"|''[^''\r\n]*''|\S+)',
        '(?i)((?:token|api[_-]?key|secret|password)=)[^&\s]+',
        '(?i)(cookie\s*[:=]\s*)\S+'
    )

    foreach ($pattern in $patterns) {
        $text = $text -replace $pattern, '$1<redacted>'
    }

    $text = $text -replace '(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b', '<redacted>'
    if ($text.Length -gt $MaxChars) {
        return $text.Substring(0, $MaxChars)
    }
    return $text
}
