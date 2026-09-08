param([switch]$Execute)
# One-time checkpoint cleanup, replayable only for the resources captured below.
# This is not a general prune utility and cannot retire newer task containers.
$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$taskStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$taskReportDir = Join-Path $taskRoot "evidence/operations/hygiene/$taskStamp"
New-Item -ItemType Directory -Path $taskReportDir -Force | Out-Null
$taskKeepContainers = @('expertauth-oss-core-a','expertauth-oss-postgres')
$taskKeepImages = @('expertauth-oss-core:12.2.0-probe','expertauth-node-react:0.0.5','expertauth-python-app:0.1.0','expertauth-kc-headless:0.1.0','expertauth-kc-headless-postgres:0.1.0','expertauth-kc-clients-node:0.0.1')
$taskStart = [DateTimeOffset]::Parse('2026-09-08T21:08:23Z')
$taskOriginalReport = Join-Path $taskRoot 'evidence/operations/hygiene/20260908T223704Z'
$taskApprovedContainers = @(Get-Content -LiteralPath (Join-Path $taskOriginalReport 'containers-before.json') -Raw | ConvertFrom-Json | Where-Object { $_.Retire })
$taskOriginalPlan = Get-Content -LiteralPath (Join-Path $taskOriginalReport 'plan.json') -Raw | ConvertFrom-Json
$taskOriginalResult = Get-Content -LiteralPath (Join-Path $taskOriginalReport 'result.json') -Raw | ConvertFrom-Json
function Docker-Read([string[]]$Arguments) {
    $taskResult = & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker read failed: $($Arguments[0])" }
    return $taskResult
}
function Safe-TaskPath([string]$Relative) {
    $taskResolved = [IO.Path]::GetFullPath((Join-Path $taskRoot $Relative))
    if (-not $taskResolved.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Path escapes ExpertAuth workspace' }
    # Refuse junction/symlink ancestors; lexical containment alone is insufficient.
    $taskAncestor = $taskResolved
    while ($taskAncestor -and $taskAncestor -ne $taskRoot) {
        if (Test-Path -LiteralPath $taskAncestor) {
            $taskEntry = Get-Item -LiteralPath $taskAncestor -Force
            if ($taskEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refuse cleanup through a reparse point' }
        }
        $taskAncestor = Split-Path -Parent $taskAncestor
    }
    return $taskResolved
}
$taskIds = @(Docker-Read @('ps','-aq','--filter','name=expertauth'))
$taskContainers = if ($taskIds.Count) { @(Docker-Read (@('inspect') + $taskIds) | ConvertFrom-Json) } else { @() }
$taskContainers = @($taskContainers | Where-Object { $_.Name.StartsWith('/expertauth-') })
foreach ($taskItem in $taskContainers) {
    if ([DateTimeOffset]::Parse($taskItem.Created) -lt $taskStart) { throw "Preexisting container requires separate review: $($taskItem.Name)" }
}
$taskRetire = @($taskContainers | Where-Object { $_.Id -in $taskApprovedContainers.Id -and $_.Name.TrimStart('/') -notin $taskKeepContainers })
$taskSafeInventory = @($taskContainers | ForEach-Object { [PSCustomObject]@{Id=$_.Id; Name=$_.Name; Image=$_.Image; Running=$_.State.Running; Mounts=@($_.Mounts | Select-Object Type,Name,Source,Destination); Retire=($_.Id -in $taskRetire.Id)} })
$taskSafeInventory | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $taskReportDir 'containers-before.json')
$taskImageLines = @(Docker-Read @('image','ls','--filter','reference=expertauth*','--format','{{.Repository}}:{{.Tag}}'))
$taskDeleteTags = @($taskImageLines | Where-Object { $_ -in $taskOriginalPlan.RemoveImageTags -and $_ -notin $taskKeepImages })
$taskScratch = @('.cache/engine-build-1788904893131443100','.cache/oss-runtime-image','.cache/runtime-license-probe-01','.cache/runtime-license-probe-02','.cache/extracted-checkpoints/20260908T222718Z-a632c0','.cache/extracted-checkpoints/20260908T222920Z-23f3d2')
$taskScratch = @($taskScratch | Where-Object { Test-Path -LiteralPath (Safe-TaskPath $_) })
$taskPlan = [PSCustomObject]@{Execute=[bool]$Execute; RetireContainers=@($taskRetire | ForEach-Object { $_.Name }); RemoveImageTags=$taskDeleteTags; RemoveScratch=$taskScratch; KeepImages=$taskKeepImages; VolumesDeleted=@(); UnrelatedResourcesTouched=$false}
$taskPlan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskReportDir 'plan.json')
if (-not $Execute) { $taskPlan | ConvertTo-Json -Depth 5; exit }

# All producers have stopped. Stop the retired labs together; never stop shared
# services or delete volumes. Preserve H2 data that lived in writable layers.
if ($taskRetire.Count) {
    & docker stop --timeout 10 @($taskRetire.Id)
    if ($LASTEXITCODE -ne 0) { throw 'A task container failed to stop; no removal attempted' }
}
$taskH2Names = @('expertauth-foundation-kc','expertauth-kc-headless-server','expertauth-kc-clients-engine')
foreach ($taskContainer in $taskRetire) {
    $taskName=$taskContainer.Name.TrimStart('/')
    if ($taskName -in $taskH2Names) {
        $taskBackup=Safe-TaskPath ".runtime/retired-labs/$taskStamp/$taskName/h2"
        New-Item -ItemType Directory -Path $taskBackup -Force | Out-Null
        & docker cp "$($taskContainer.Id):/opt/keycloak/data/h2/." $taskBackup
        if ($LASTEXITCODE -ne 0) { throw "H2 backup failed; retain container $taskName" }
        @(Get-ChildItem -LiteralPath $taskBackup -File -Recurse | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskReportDir "$taskName-backup-hashes.json")
    }
    if ($taskName.EndsWith('-pg') -and -not @($taskContainer.Mounts | Where-Object { $_.Destination -eq '/var/lib/postgresql/data' }).Count) { throw 'Refuse removing database container without persistent data mount' }
}
if ($taskRetire.Count) {
    & docker rm @($taskRetire.Id)
    if ($LASTEXITCODE -ne 0) { throw 'Container removal incomplete' }
}
if ($taskDeleteTags.Count) {
    & docker image rm @taskDeleteTags
    if ($LASTEXITCODE -ne 0) { throw 'Some obsolete images remain referenced; review without force' }
}

# Only untagged images whose IDs are recorded in this repository's real build
# logs qualify. Tagged images, base digests and images used elsewhere are retained.
$taskKnownBuildIds = @($taskOriginalResult.RemovedKnownTaskDangling | ForEach-Object { $_.Substring(7) })
$taskUsedImages = @((Docker-Read @('ps','-aq')) | ForEach-Object { Docker-Read @('inspect','--format','{{.Image}}',$_) } | Sort-Object -Unique)
$taskDangling = @(Docker-Read @('image','ls','--filter','dangling=true','--no-trunc','--format','{{.ID}}') | Sort-Object -Unique)
$taskRemovedDangling=@()
foreach ($taskId in $taskDangling) {
    if ($taskId -in $taskUsedImages -or -not @($taskKnownBuildIds | Where-Object { $taskId.Substring(7).StartsWith($_) }).Count) { continue }
    $taskImage = @(& docker image inspect $taskId 2>$null | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { continue }
    if ($taskImage[0].RepoTags.Count -or $taskImage[0].RepoDigests.Count -or [DateTimeOffset]::Parse($taskImage[0].Created) -lt $taskStart) { continue }
    & docker image rm $taskId 2>$null
    if ($LASTEXITCODE -eq 0) { $taskRemovedDangling += $taskId }
}
$taskFreedScratch=0L
foreach ($taskRelative in $taskScratch) {
    $taskTarget=Safe-TaskPath $taskRelative
    if (-not (Test-Path -LiteralPath $taskTarget)) { continue }
    if (-not $taskTarget.StartsWith((Safe-TaskPath '.cache')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Scratch target is outside exact cache boundary' }
    $taskRawLogs=Join-Path $taskTarget 'raw-command-logs'
    if (Test-Path -LiteralPath $taskRawLogs) {
        $taskLogBackup=Safe-TaskPath ".runtime/retired-proof-logs/$taskStamp/$(Split-Path $taskTarget -Leaf)"
        New-Item -ItemType Directory -Path $taskLogBackup -Force | Out-Null
        Copy-Item -LiteralPath $taskRawLogs -Destination $taskLogBackup -Recurse
    }
    $taskFreedScratch += [long](Get-ChildItem -LiteralPath $taskTarget -File -Recurse | Measure-Object -Property Length -Sum).Sum
    Remove-Item -LiteralPath $taskTarget -Recurse -Force
}
$taskNetworks=@(Docker-Read @('network','ls','--filter','name=expertauth','--format','{{.Name}}'))
$taskRemovedNetworks=@()
foreach ($taskNetwork in $taskNetworks) {
    if ($taskNetwork -notin @('expertauth-foundation-kc','expertauth-kc-clients-proof','expertauth-kc-headless-proof','expertauth-kc-sessions-proof')) { continue }
    $taskNetworkState=@(Docker-Read @('network','inspect',$taskNetwork) | ConvertFrom-Json)[0]
    if (@($taskNetworkState.Containers.PSObject.Properties).Count) { continue }
    & docker network rm $taskNetwork
    if ($LASTEXITCODE -eq 0) { $taskRemovedNetworks += $taskNetwork }
}
$taskSummary=[PSCustomObject]@{ContainersRemoved=$taskRetire.Count; TaggedImagesRemoved=$taskDeleteTags.Count; RemovedKnownTaskDangling=$taskRemovedDangling; ScratchBytesRemoved=$taskFreedScratch; NetworksRemoved=$taskRemovedNetworks; VolumesDeleted=@(); DatabaseBackups=".runtime/retired-labs/$taskStamp"; PreservedCoreContainers=$taskKeepContainers; Complete=$false}
$taskSummary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $taskReportDir 'result.json')
$taskSummary | ConvertTo-Json -Depth 6
