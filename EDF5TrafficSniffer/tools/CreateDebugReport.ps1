[CmdletBinding()]
param(
    [string]$Session = '',
    [string]$Output = '',
    [string]$GameRoot = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$aliasMaps = @{
    steam = @{}
    lobby = @{}
    endpoint = @{}
    identity = @{}
    url = @{}
}

function Get-StableAlias {
    param([string]$Kind, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $map = $aliasMaps[$Kind]
    if (-not $map.ContainsKey($Value)) {
        $map[$Value] = '{0}_{1}' -f $Kind, ($map.Count + 1)
    }
    return $map[$Value]
}

function Sanitize-Text {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
    $result = $Value
    $result = [regex]::Replace(
        $result,
        '(?i)Bearer\s+[A-Za-z0-9._~+/=-]+',
        '<redacted_authorization>')
    $result = [regex]::Replace(
        $result,
        '(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie|token|ticket|password|secret)\s*[:=]\s*(?:Basic\s+|Bearer\s+)?[^\s,;]+',
        '<redacted_credential>')
    $result = [regex]::Replace(
        $result,
        '(?i)\b(persona|persona_name|friend_name|player_name|display_name|user_name)\s*[:=]\s*([^\r\n,;]+)',
        { param($match)
            return $match.Groups[1].Value + '=' +
                (Get-StableAlias 'identity' $match.Groups[2].Value.Trim())
        })
    $result = [regex]::Replace(
        $result,
        '(?i)\b(host|hostname|domain|node|endpoint|remote_ip|local_ip)\s*[:=]\s*([^\s,;]+)',
        { param($match)
            return $match.Groups[1].Value + '=' +
                (Get-StableAlias 'endpoint' $match.Groups[2].Value)
        })
    $result = [regex]::Replace(
        $result,
        '(?<![0-9])7[0-9]{16}(?![0-9])',
        { param($match) Get-StableAlias 'steam' $match.Value })
    $result = [regex]::Replace(
        $result,
        '(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?',
        { param($match) Get-StableAlias 'endpoint' $match.Value })
    $result = [regex]::Replace(
        $result,
        '\[[0-9A-Fa-f:]{2,}\](?::[0-9]{1,5})?',
        { param($match) Get-StableAlias 'endpoint' $match.Value })
    $result = [regex]::Replace(
        $result,
        '(?i)https?://[^\s"''<>]+',
        { param($match) Get-StableAlias 'url' $match.Value })
    $result = [regex]::Replace(
        $result,
        '(?i)[A-Z]:\\[^\r\n"'']+',
        '<redacted_path>')
    $result = [regex]::Replace(
        $result,
        '\\\\[^\s\\]+\\[^\r\n"'']+',
        '<redacted_path>')
    $result = [regex]::Replace(
        $result,
        '(?i)\b0x[0-9a-f]{9,16}\b',
        '<redacted_address>')
    $result = [regex]::Replace(
        $result,
        '(?i)\b(context|client|user|friends|matchmaking|networking|http|address|exception_address|access_address|instruction_pointer|stack_pointer|frame_pointer|register_[a-z0-9]+|return_address_[0-9]+|stack_word_[0-9]+)\s*[:=]\s*(?:0x[0-9a-f]+|[0-9]{9,20})',
        '$1=<redacted_address>')
    $result = [regex]::Replace(
        $result,
        '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=])',
        '<redacted_blob>')
    return $result
}

function Sanitize-Scalar {
    param([string]$Key, $Value)
    $lower = $Key.ToLowerInvariant()
    if (($Value -is [ValueType]) -and
        $lower -match '(^|_)(bytes|size|length|offset|count|limit|enabled|truncated)$') {
        return $Value
    }
    if ($lower -match '(^|_)(authorization|cookie|ticket|token|password|secret|header|body|chat|payload|preview|user_agent)($|_)') {
        return '<redacted>'
    }
    if ($lower -match 'lobby.*id|lobby_steam_id') {
        return Get-StableAlias 'lobby' ([string]$Value)
    }
    if ($lower -match 'steam_id|peer_steam|user_steam|source_user|owner_steam') {
        return Get-StableAlias 'steam' ([string]$Value)
    }
    if ($lower -eq 'context') {
        if ($Value -is [ValueType] -or
            ([string]$Value) -match '^(?i:0x[0-9a-f]{9,16}|[0-9]{9,20})$') {
            return '<redacted_address>'
        }
        return Sanitize-Text ([string]$Value)
    }
    if ($lower -match '^(client|user|friends|matchmaking|networking|http|address|exception_address|access_address|instruction_pointer|stack_pointer|frame_pointer)$' -or
        $lower -match '^(register_[a-z0-9]+|return_address_[0-9]+|stack_word_[0-9]+)$') {
        return '<redacted_address>'
    }
    if ($lower -match 'endpoint|(^|_)(ip|host|hostname|domain|node)($|_)|remote_ip|local_ip|address_text') {
        return Get-StableAlias 'endpoint' ([string]$Value)
    }
    if ($lower -match 'persona|friend_name|display_name|player_name|user_name') {
        return Get-StableAlias 'identity' ([string]$Value)
    }
    if ($lower -match '(^|_)(url|uri)($|_)') {
        return Get-StableAlias 'url' ([string]$Value)
    }
    if ($lower -match '(^|_)(path|directory|executable|plugin_path|artifact)($|_)') {
        $leaf = [IO.Path]::GetFileName(([string]$Value).Replace('/', '\'))
        if ([string]::IsNullOrWhiteSpace($leaf)) { return '<redacted_path>' }
        return $leaf
    }
    if ($lower -match '(^|_)(value|data)$' -and $Value -is [string]) {
        return '<redacted_value>'
    }
    if ($Value -is [string]) { return Sanitize-Text $Value }
    return $Value
}

function Sanitize-Value {
    param($Value, [string]$Key = '')
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $output = [ordered]@{}
        foreach ($entry in $Value.GetEnumerator()) {
            $name = [string]$entry.Key
            if ($name.ToLowerInvariant() -eq 'payload') { continue }
            $output[$name] = Sanitize-Value $entry.Value $name
        }
        return [pscustomobject]$output
    }
    if ($Value -is [pscustomobject]) {
        $output = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $name = [string]$property.Name
            if ($name.ToLowerInvariant() -eq 'payload') { continue }
            $output[$name] = Sanitize-Value $property.Value $name
        }
        return [pscustomobject]$output
    }
    if (($Value -is [System.Collections.IEnumerable]) -and
        -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) { $items += ,(Sanitize-Value $item $Key) }
        return $items
    }
    return Sanitize-Scalar $Key $Value
}

function Sanitize-JsonLineFast {
    param([string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return '' }
    if ($Line[0] -ne '{' -or $Line[$Line.Length - 1] -ne '}') {
        return $null
    }
    if ($Line -notmatch '(?i)steam|lobby|endpoint|remote_ip|local_ip|address_text|host|hostname|domain|node|persona|friend_name|display_name|player_name|user_name|authorization|cookie|ticket|token|password|secret|header|body|chat|preview|user_agent|value|data|url|uri|path|directory|executable|artifact|context|client|friends|matchmaking|networking|http|exception_address|access_address|instruction_pointer|stack_pointer|frame_pointer|register_|return_address_|stack_word_|0x[0-9a-f]{9,16}|Bearer|https?://|[A-Z]:\\\\|(?:[0-9]{1,3}\.){3}[0-9]{1,3}') {
        return $Line
    }

    $result = $Line
    $result = [regex]::Replace(
        $result,
        '(?i)("[^"]*lobby[^"]*id[^"]*"\s*:\s*)(?:"((?:\\.|[^"\\])*)"|([0-9]+))',
        { param($match)
            $value = if ($match.Groups[2].Success) {
                $match.Groups[2].Value
            } else {
                $match.Groups[3].Value
            }
            return $match.Groups[1].Value + '"' +
                (Get-StableAlias 'lobby' $value) + '"'
        })
    $result = [regex]::Replace(
        $result,
        '(?i)("(?![^"]*lobby)[^"]*steam_id[^"]*"\s*:\s*)(?:"((?:\\.|[^"\\])*)"|([0-9]+))',
        { param($match)
            $value = if ($match.Groups[2].Success) {
                $match.Groups[2].Value
            } else {
                $match.Groups[3].Value
            }
            return $match.Groups[1].Value + '"' +
                (Get-StableAlias 'steam' $value) + '"'
        })
    $result = [regex]::Replace(
        $result,
        '(?i)("(?:remote_endpoint|local_endpoint|endpoint|remote_ip|local_ip|address_text|host|hostname|domain|node)"\s*:\s*)"((?:\\.|[^"\\])*)"',
        { param($match)
            return $match.Groups[1].Value + '"' +
                (Get-StableAlias 'endpoint' $match.Groups[2].Value) + '"'
        })
    $result = [regex]::Replace(
        $result,
        '(?i)("(?:persona|persona_name|friend_name|display_name|player_name|user_name)"\s*:\s*)"((?:\\.|[^"\\])*)"',
        { param($match)
            return $match.Groups[1].Value + '"' +
                (Get-StableAlias 'identity' $match.Groups[2].Value) + '"'
        })
    $result = [regex]::Replace(
        $result,
        '(?i)("[^"]*(?:authorization|cookie|ticket|token|password|secret|header|body|chat|preview|user_agent)[^"]*"\s*:\s*)"(?:\\.|[^"\\])*"',
        '$1"<redacted>"')
    $result = [regex]::Replace(
        $result,
        '(?i)("(?:authorization|cookie|ticket|token|password|secret|header|body|chat|preview|user_agent)"\s*:\s*)(?:[0-9]+|true|false|null)',
        '$1"<redacted>"')
    $result = [regex]::Replace(
        $result,
        '(?i)("[^"]*(?:value|data|user_agent)"\s*:\s*)"(?:\\.|[^"\\])*"',
        '$1"<redacted_value>"')
    $result = [regex]::Replace(
        $result,
        '(?i)("(?:url|uri)"\s*:\s*)"((?:\\.|[^"\\])*)"',
        { param($match)
            return $match.Groups[1].Value + '"' +
                (Get-StableAlias 'url' $match.Groups[2].Value) + '"'
        })
    $result = [regex]::Replace(
        $result,
        '(?i)("(?:path|directory|executable|plugin_path|artifact)"\s*:\s*)"(?:\\.|[^"\\])*"',
        '$1"<redacted_path>"')
    $result = [regex]::Replace(
        $result,
        '(?i)("context"\s*:\s*)(?:"(?:0x[0-9a-f]{9,16}|[0-9]{9,20})"|-?[0-9]{9,20})',
        '$1"<redacted_address>"')
    $result = [regex]::Replace(
        $result,
        '(?i)("(?:client|user|friends|matchmaking|networking|http|address|exception_address|access_address|instruction_pointer|stack_pointer|frame_pointer|register_[a-z0-9]+|return_address_[0-9]+|stack_word_[0-9]+)"\s*:\s*)(?:"(?:\\.|[^"\\])*"|-?[0-9]+|true|false|null)',
        '$1"<redacted_address>"')
    return Sanitize-Text $result
}

function Sanitize-JsonFile {
    param([string]$Source, [string]$Destination)
    $raw = Get-Content -LiteralPath $Source -Raw -Encoding UTF8
    $parsed = $raw | ConvertFrom-Json
    $sanitized = Sanitize-Value $parsed
    $json = $sanitized | ConvertTo-Json -Depth 64
    [IO.File]::WriteAllText($Destination, $json + "`r`n",
                            [Text.UTF8Encoding]::new($false))
}

function Sanitize-JsonLines {
    param([string]$Source, [string]$Destination)
    # Large sessions take minutes on slower PCs. Without visible progress
    # testers closed the window mid-way, leaving truncated .staging folders
    # and no ZIP (2026-10-03).
    $totalLines = 0
    foreach ($ignored in [IO.File]::ReadLines($Source)) { $totalLines++ }
    $sourceName = [IO.Path]::GetFileName($Source)
    $nextProgress = 0
    $writer = [IO.StreamWriter]::new(
        $Destination, $false, [Text.UTF8Encoding]::new($false))
    try {
        $lineNumber = 0
        foreach ($line in [IO.File]::ReadLines($Source)) {
            $lineNumber++
            if ($totalLines -ge 500 -and $lineNumber -ge $nextProgress) {
                $percent = [int](100 * $lineNumber / $totalLines)
                Write-Host ("  {0}: {1}% ({2}/{3})" -f
                    $sourceName, $percent, $lineNumber, $totalLines)
                $nextProgress = $lineNumber + [Math]::Max(500, [int]($totalLines / 10))
            }
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -notmatch '(?i)"payload"\s*:') {
                $fast = Sanitize-JsonLineFast $line
                if ($null -ne $fast) {
                    $writer.WriteLine($fast)
                    continue
                }
            }
            try {
                $parsed = $line | ConvertFrom-Json
                $sanitized = Sanitize-Value $parsed
                $writer.WriteLine(($sanitized | ConvertTo-Json -Depth 64 -Compress))
            } catch {
                $fallback = [ordered]@{
                    schema = 2
                    level = 'warn'
                    layer = 'report'
                    event = 'malformed_source_line'
                    source_line = $lineNumber
                }
                $writer.WriteLine(($fallback | ConvertTo-Json -Compress))
            }
        }
    } finally {
        $writer.Dispose()
    }
}

function Write-WindowsCrashEvents {
    param([string]$SessionMetadataPath, [string]$Destination)
    try {
        $metadata = Get-Content -LiteralPath $SessionMetadataPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if ($null -eq $metadata.started_utc) { return }
        $started = [DateTimeOffset]::Parse([string]$metadata.started_utc)
        $localStart = $started.ToLocalTime().DateTime.AddMinutes(-2)
        $events = @(Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                StartTime = $localStart
            } -ErrorAction Stop |
            Where-Object {
                ($_.ProviderName -in @('Application Error',
                                       'Windows Error Reporting')) -and
                $_.Message -match '(?i)EDF5\.exe'
            } |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 20)
        if ($events.Count -eq 0) { return }
        $safe = foreach ($event in $events) {
            [ordered]@{
                schema = 2
                utc = $event.TimeCreated.ToUniversalTime().ToString('o')
                provider = [string]$event.ProviderName
                event_id = [int]$event.Id
                level = [string]$event.LevelDisplayName
                message = Sanitize-Text ([string]$event.Message)
            }
        }
        [IO.File]::WriteAllText(
            $Destination,
            (($safe | ConvertTo-Json -Depth 8) + "`r`n"),
            [Text.UTF8Encoding]::new($false))
    } catch {
        # Windows Event Log access is optional. The session report remains
        # useful on restricted accounts where this channel cannot be read.
    }
}

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($Session)) {
    $logs = Join-Path $scriptDirectory 'logs'
    if (-not (Test-Path -LiteralPath $logs -PathType Container)) {
        throw "Logs directory not found. Pass -Session explicitly."
    }
    $latest = Get-ChildItem -LiteralPath $logs -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $latest) { throw "No diagnostic session was found." }
    $Session = $latest.FullName
}

$sessionPath = [IO.Path]::GetFullPath($Session)
if (-not (Test-Path -LiteralPath $sessionPath -PathType Container)) {
    throw "Session directory does not exist: $sessionPath"
}
if (-not (Test-Path -LiteralPath (Join-Path $sessionPath 'session.json'))) {
    throw "The selected directory is not an EDF5MP diagnostic session."
}

$reportsDirectory = if ([string]::IsNullOrWhiteSpace($Output)) {
    Join-Path $scriptDirectory 'reports'
} else {
    $candidate = [IO.Path]::GetFullPath($Output)
    if ([IO.Path]::GetExtension($candidate) -ieq '.zip') {
        Split-Path -Parent $candidate
    } else {
        $candidate
    }
}
New-Item -ItemType Directory -Force -Path $reportsDirectory | Out-Null
$reportsDirectory = [IO.Path]::GetFullPath($reportsDirectory)
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss.fffZ')
$zipPath = if (-not [string]::IsNullOrWhiteSpace($Output) -and
               [IO.Path]::GetExtension($Output) -ieq '.zip') {
    [IO.Path]::GetFullPath($Output)
} else {
    Join-Path $reportsDirectory ("EDF5MP-report-$timestamp.zip")
}
if (Test-Path -LiteralPath $zipPath) {
    throw "Refusing to overwrite an existing report: $zipPath"
}

$staging = Join-Path $reportsDirectory ('.staging-' + [Guid]::NewGuid().ToString('N'))
$stagingFull = [IO.Path]::GetFullPath($staging)
$safePrefix = $reportsDirectory.TrimEnd('\') + '\'
if (-not $stagingFull.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe staging path: $stagingFull"
}
New-Item -ItemType Directory -Path $stagingFull | Out-Null
Write-Host "Creating sanitized report for session $([IO.Path]::GetFileName($sessionPath))."
Write-Host 'This can take a few minutes for long sessions. Do not close this window'
Write-Host 'until it prints "Created sanitized report".'

try {
    foreach ($name in @('session.json', 'status.json', 'health.json')) {
        $source = Join-Path $sessionPath $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Sanitize-JsonFile $source (Join-Path $stagingFull $name)
        }
    }
    Write-WindowsCrashEvents (Join-Path $sessionPath 'session.json') (Join-Path $stagingFull 'windows-crash-events.json')

    $eventIndex = 0
    Get-ChildItem -LiteralPath $sessionPath -File -Filter 'events*.jsonl' |
        Sort-Object @{ Expression = {
            if ($_.Name -eq 'events.jsonl') { return 1 }
            if ($_.Name -match '^events-([0-9]+)\.jsonl$') {
                return [int]$Matches[1]
            }
            return [int]::MaxValue
        } } | ForEach-Object {
            $eventIndex++
            $targetName = if ($eventIndex -eq 1) {
                'events.jsonl'
            } else {
                'events-{0:D4}.jsonl' -f $eventIndex
            }
            Sanitize-JsonLines $_.FullName (Join-Path $stagingFull $targetName)
        }

    foreach ($folderName in @('crashes', 'snapshots')) {
        $sourceFolder = Join-Path $sessionPath $folderName
        if (-not (Test-Path -LiteralPath $sourceFolder -PathType Container)) {
            continue
        }
        $targetFolder = Join-Path $stagingFull $folderName
        New-Item -ItemType Directory -Force -Path $targetFolder | Out-Null
        Get-ChildItem -LiteralPath $sourceFolder -Recurse -File |
            Where-Object { $_.Extension -in @('.json', '.jsonl') } |
            ForEach-Object {
                $relative = $_.FullName.Substring($sourceFolder.Length).TrimStart('\')
                $target = Join-Path $targetFolder $relative
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) |
                    Out-Null
                if ($_.Extension -eq '.jsonl') {
                    Sanitize-JsonLines $_.FullName $target
                } else {
                    Sanitize-JsonFile $_.FullName $target
                }
            }
    }

    if ([string]::IsNullOrWhiteSpace($GameRoot)) {
        $candidateRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory '..\..'))
        if (Test-Path -LiteralPath (Join-Path $candidateRoot 'ModLoader.log')) {
            $GameRoot = $candidateRoot
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($GameRoot)) {
        $loaderLog = Join-Path ([IO.Path]::GetFullPath($GameRoot)) 'ModLoader.log'
        if (Test-Path -LiteralPath $loaderLog -PathType Leaf) {
            $tail = Get-Content -LiteralPath $loaderLog -Tail 2000
            $safeLines = foreach ($line in $tail) { Sanitize-Text ([string]$line) }
            [IO.File]::WriteAllLines(
                (Join-Path $stagingFull 'ModLoader-sanitized.log'),
                $safeLines,
                [Text.UTF8Encoding]::new($false))
        }
    }

    $notice = @"
EDF5 More Players Lab - sanitized diagnostic report

This archive intentionally excludes minidumps (*.dmp), raw payload files,
packet previews, authentication material, exact Steam IDs, IP endpoints,
persona names, personal paths and absolute process addresses.

When available, windows-crash-events.json contains sanitized EDF5 Application
Error/Windows Error Reporting entries recorded after this session started.

The raw session remains at:
  $sessionPath

If a developer explicitly requests the minidump, treat it as sensitive and
send it separately only after reviewing that request.
"@
    [IO.File]::WriteAllText(
        (Join-Path $stagingFull 'REPORT_INFO.txt'),
        (Sanitize-Text $notice),
        [Text.UTF8Encoding]::new($false))

    $manifestFiles = Get-ChildItem -LiteralPath $stagingFull -Recurse -File |
        Sort-Object FullName
    $manifest = [ordered]@{
        schema = 2
        created_utc = (Get-Date).ToUniversalTime().ToString('o')
        source_session = Split-Path -Leaf $sessionPath
        excludes = @('*.dmp', 'payloads*.bin', 'raw packet previews', 'secrets')
        files = @()
    }
    foreach ($file in $manifestFiles) {
        $manifest.files += [ordered]@{
            path = $file.FullName.Substring($stagingFull.Length).TrimStart('\')
            bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $stagingFull 'manifest.json'),
        (($manifest | ConvertTo-Json -Depth 8) + "`r`n"),
        [Text.UTF8Encoding]::new($false))

    Compress-Archive -Path (Join-Path $stagingFull '*') -DestinationPath $zipPath
} finally {
    if (Test-Path -LiteralPath $stagingFull) {
        $verified = [IO.Path]::GetFullPath($stagingFull)
        if ($verified.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $verified -Recurse -Force
        }
    }
}

Write-Host "Created sanitized report: $zipPath"
Write-Output $zipPath
