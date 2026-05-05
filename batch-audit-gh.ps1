<#
.SYNOPSIS
Batch run audits for multiple leads via GitHub Actions

.DESCRIPTION
Finds leads with domains and runs audit-lead.js via GitHub Actions.
Extracts results to ops/audit-review/ for quality review.

.PARAMETER Count
Number of leads to audit (default: 50)

.PARAMETER StartRange
Optional profile range to start from (e.g., "3600-3699")

.PARAMETER DryRun
Show what would be run without triggering workflows

.EXAMPLE
.\batch-audit-gh.ps1 -Count 50
.\batch-audit-gh.ps1 -Count 10 -StartRange "3600-3699" -DryRun
#>

param(
    [int]$Count = 50,
    [string]$StartRange,
    [switch]$DryRun,
    [string]$Repo = "GalToast/website-audit-engine"
)

$ErrorActionPreference = "Stop"

# Config
$OpenSSLPath = "C:\Program Files\Git\usr\bin\openssl.exe"
$KeyFile = "$env:USERPROFILE\.audit-encryption-key"
$ReviewBase = "ops\audit-review"

function Remove-WorkflowRun {
    param([string]$RepoName, [string]$WorkflowRunId)
    if (-not $WorkflowRunId) { return }
    & gh run delete $WorkflowRunId --repo $RepoName 2>&1 | Out-Null
}

function Get-EncryptedArtifact {
    param(
        [string]$RepoName,
        [string]$WorkflowRunId,
        [string]$DestinationDir
    )

    $maxAttempts = 6
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        if (Test-Path $DestinationDir) {
            Get-ChildItem -Path $DestinationDir -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }

        & gh run download $WorkflowRunId -D $DestinationDir --repo $RepoName 2>&1 | Out-Null
        $encrypted = Get-ChildItem -Path $DestinationDir -Recurse -Filter "*.enc" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($encrypted) {
            return $encrypted
        }

        if ($attempt -lt $maxAttempts) {
            Start-Sleep -Seconds 3
        }
    }

    return $null
}

function Get-RunArtifactMetadata {
    param(
        [string]$RepoName,
        [string]$WorkflowRunId
    )

    $response = & gh api "repos/$RepoName/actions/runs/$WorkflowRunId/artifacts" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $response) {
        return $null
    }

    $payload = $response | ConvertFrom-Json
    foreach ($artifact in @($payload.artifacts)) {
        if (-not $artifact.name) { continue }

        if ($artifact.name -match '^audit-(\d+)-(.*)-encrypted$') {
            return @{
                LeadId = $Matches[1]
                BatchToken = $Matches[2]
                ArtifactName = $artifact.name
            }
        }

        if ($artifact.name -match '^audit-(\d+)-encrypted$') {
            return @{
                LeadId = $Matches[1]
                BatchToken = ""
                ArtifactName = $artifact.name
            }
        }
    }

    return $null
}

function Get-ExtractedAuditMetadata {
    param([string]$ReviewDir)

    $auditJson = Get-ChildItem -Path $ReviewDir -Recurse -Filter "audit-*.json" -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $auditJson) {
        return $null
    }

    $actualLeadId = $null
    if ($auditJson.BaseName -match '^audit-(\d+)$') {
        $actualLeadId = $Matches[1]
    }

    $payload = $null
    try {
        $payload = Get-Content -Path $auditJson.FullName -Raw | ConvertFrom-Json
    } catch {
        $payload = $null
    }

    $actualDomain = $null
    if ($payload) {
        if ($payload.domain) {
            $actualDomain = [string]$payload.domain
        } elseif ($payload.enrichment -and $payload.enrichment.fieldConfidence -and $payload.enrichment.fieldConfidence.domain -and $payload.enrichment.fieldConfidence.domain.value) {
            $actualDomain = [string]$payload.enrichment.fieldConfidence.domain.value
        }
    }

    return @{
        AuditJsonPath = $auditJson.FullName
        LeadId = $actualLeadId
        Domain = $actualDomain
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BATCH AUDIT RUNNER (GitHub Actions)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Find leads with domains
Write-Host "Scanning profiles for domains..." -ForegroundColor Yellow

$leads = @()
$profileFiles = Get-ChildItem -Path "leads\profiles" -Recurse -Filter "profile.md"

foreach ($file in $profileFiles) {
    if ($leads.Count -ge $Count) { break }
    
    # Parse path: leads/profiles/3600-3699/3648-iq-motorsports-llc/profile.md
    $pathParts = $file.FullName.Split('\')
    $rangeIdx = $pathParts.IndexOf("profiles") + 1
    if ($rangeIdx -ge $pathParts.Count) { continue }
    
    $profileRange = $pathParts[$rangeIdx]
    $folderName = $pathParts[$rangeIdx + 1]
    
    # Extract lead ID from folder name (e.g., "3648-iq-motorsports-llc" -> "3648")
    if ($folderName -match '^(\d+)') {
        $leadId = $Matches[1]
    } else {
        continue
    }
    
    # Skip if StartRange specified and we haven't reached it
    if ($StartRange -and $profileRange -lt $StartRange) { continue }
    
    # Extract domain from profile
    $content = Get-Content $file.FullName -Raw
    if ($content -match '\*\*Website:\*\*\s*https?://([^\s/\)]+)') {
        $domain = $Matches[1].Trim()
        
        # Filter out invalid domains
        if ($domain -match '^(N/A|none|pending|tbd|localhost|example\.com)$') {
            continue
        }
        
        # Skip if already has audit in evidence folder
        $evidencePath = Join-Path $file.DirectoryName "evidence"
        if (Test-Path $evidencePath) {
            $auditEvidence = Get-ChildItem $evidencePath -Filter "*audit*" -ErrorAction SilentlyContinue
            if ($auditEvidence) {
                Write-Host "  Skipping $leadId (already has audit evidence)" -ForegroundColor DarkGray
                continue
            }
        }
        
        $leads += @{
            LeadId = $leadId
            Domain = $domain
            ProfileRange = $profileRange
            FolderName = $folderName
        }
    }
}

Write-Host ""
Write-Host "Found $($leads.Count) leads with domains to audit" -ForegroundColor Green

if ($leads.Count -eq 0) {
    Write-Host "No leads found. Check profile format or try different StartRange." -ForegroundColor Yellow
    exit 0
}

if ($DryRun) {
    Write-Host ""
    Write-Host "DRY RUN - Would audit these leads:" -ForegroundColor Yellow
    $leads | ForEach-Object {
        Write-Host "  $($_.LeadId): $($_.Domain) [$($_.ProfileRange)]"
    }
    exit 0
}

Write-Host ""
Write-Host "Starting PARALLEL batch audit..." -ForegroundColor Yellow
Write-Host "Triggering $($leads.Count) workflows (GitHub allows ~20 concurrent)" -ForegroundColor DarkGray
Write-Host ""

$batchTriggerStartUtc = (Get-Date).ToUniversalTime()
$batchToken = Get-Date -Format "yyyyMMddHHmmssfff"

# Phase 1: Trigger all workflows
$runTracker = @()

foreach ($lead in $leads) {
    Write-Host "Triggering: $($lead.LeadId) - $($lead.Domain)" -ForegroundColor Cyan
    
    # Trigger workflow with properly quoted parameters
    $leadIdParam = "lead_id=$($lead.LeadId)"
    $domainParam = "domain=$($lead.Domain)"
    $rangeParam = "profile_range=$($lead.ProfileRange)"
    $batchTokenParam = "batch_token=$batchToken"
    
    $triggerResult = & gh workflow run audit-lead.yml `
        -f $leadIdParam `
        -f $domainParam `
        -f $rangeParam `
        -f $batchTokenParam `
        --repo $Repo 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED to trigger: $triggerResult" -ForegroundColor Red
        $runTracker += @{ LeadId = $lead.LeadId; RunId = $null; Status = "TriggerFailed"; Domain = $lead.Domain }
    } else {
        $runTracker += @{
            LeadId = $lead.LeadId
            RunId = "pending"
            Status = "Triggered"
            Domain = $lead.Domain
            TriggeredAtUtc = (Get-Date).ToUniversalTime()
        }
    }
    
    # Small delay to avoid rate limiting
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "All workflows triggered. Waiting for completed runs with batch token $batchToken..." -ForegroundColor Yellow
Write-Host "Monitoring 0 runs..." -ForegroundColor Yellow
Write-Host ""

# Phase 3: Poll for completion and collect results
$results = @()
$successful = 0
$failed = 0
$startTime = Get-Date
$timeoutMinutes = 15  # Max time for all runs

while ($runTracker.Where({$_.Status -eq "Triggered"}).Count -gt 0) {
    # Check timeout
    if (((Get-Date) - $startTime).TotalMinutes -gt $timeoutMinutes) {
        Write-Host "Timeout reached. Some runs may still be in progress." -ForegroundColor Yellow
        break
    }
    
    # Discover completed runs by matching artifact metadata back to this batch token.
    $recentRunLimit = [Math]::Max($leads.Count * 6, 30)
    $recentRuns = & gh run list --workflow=audit-lead.yml --limit $recentRunLimit --json databaseId,status,conclusion,createdAt --repo $Repo 2>&1 | ConvertFrom-Json
    $candidateRuns = $recentRuns |
        Where-Object { ([datetime]$_.createdAt).ToUniversalTime() -ge $batchTriggerStartUtc.AddSeconds(-5) } |
        Sort-Object { ([datetime]$_.createdAt).ToUniversalTime() }

    foreach ($candidate in $candidateRuns) {
        $alreadyAssigned = $runTracker | Where-Object { $_.RunId -eq $candidate.databaseId } | Select-Object -First 1
        if ($alreadyAssigned) { continue }

        $artifactMeta = Get-RunArtifactMetadata -RepoName $Repo -WorkflowRunId $candidate.databaseId
        if (-not $artifactMeta) { continue }
        if ($artifactMeta.BatchToken -ne $batchToken) { continue }

        $matchingLead = $runTracker | Where-Object {
            $_.LeadId -eq $artifactMeta.LeadId -and $_.Status -eq "Triggered" -and (-not $_.RunId -or $_.RunId -eq "pending")
        } | Select-Object -First 1

        if ($matchingLead) {
            $matchingLead.RunId = $candidate.databaseId
        }
    }

    foreach ($run in $runTracker) {
        if ($run.Status -ne "Triggered") { continue }
        if (-not $run.RunId -or $run.RunId -eq "pending") { continue }
        
        # Check status
        $status = & gh run view $run.RunId --json status,conclusion --repo $Repo 2>&1 | ConvertFrom-Json
        
        if ($status.status -eq "completed") {
            $run.Status = $status.conclusion
            
            if ($status.conclusion -eq "success") {
                Write-Host "  DONE: $($run.LeadId) - SUCCESS" -ForegroundColor Green
                
                # Download and decrypt
                $tempDir = Join-Path $env:TEMP "audit-$($run.LeadId)"
                
                if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
                New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                
                # Download artifact
                $encryptedFile = Get-EncryptedArtifact -RepoName $Repo -WorkflowRunId $run.RunId -DestinationDir $tempDir
                
                if ($encryptedFile) {
                    # Decrypt
                    $decryptedFile = Join-Path $tempDir "audit-results.tar.gz"
                    & $OpenSSLPath enc -aes-256-cbc -d -pbkdf2 -in $encryptedFile.FullName -out $decryptedFile -pass file:$KeyFile 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $decryptedFile)) {
                        Write-Host "  DECRYPT FAILED: $($run.LeadId)" -ForegroundColor Red
                        $failed++
                        $results += @{ LeadId = $run.LeadId; Status = "DecryptFailed"; Domain = $run.Domain }
                        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        Remove-WorkflowRun -RepoName $Repo -WorkflowRunId $run.RunId
                        continue
                    }
                    
                    # Extract to review folder
                    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                    $reviewDir = Join-Path $ReviewBase "lead-$($run.LeadId)-$timestamp"
                    New-Item -ItemType Directory -Path $reviewDir -Force | Out-Null
                    
                    tar -xzf $decryptedFile -C $reviewDir 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0 -or -not (Get-ChildItem $reviewDir -Force | Select-Object -First 1)) {
                        Write-Host "  EXTRACT FAILED: $($run.LeadId)" -ForegroundColor Red
                        $failed++
                        $results += @{ LeadId = $run.LeadId; Status = "ExtractFailed"; Domain = $run.Domain }
                        Remove-Item $reviewDir -Recurse -Force -ErrorAction SilentlyContinue
                        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        Remove-WorkflowRun -RepoName $Repo -WorkflowRunId $run.RunId
                        continue
                    }

                    $auditMeta = Get-ExtractedAuditMetadata -ReviewDir $reviewDir
                    $actualLeadId = if ($auditMeta -and $auditMeta.LeadId) { [string]$auditMeta.LeadId } else { [string]$run.LeadId }
                    $actualDomain = if ($auditMeta -and $auditMeta.Domain) { [string]$auditMeta.Domain } else { [string]$run.Domain }

                    if ($actualLeadId -ne [string]$run.LeadId) {
                        Write-Host "  WARNING: extracted audit belongs to lead $actualLeadId (expected $($run.LeadId))" -ForegroundColor Yellow
                    }

                    $actualReviewDir = $reviewDir
                    if ($actualLeadId -ne [string]$run.LeadId) {
                        $renamedReviewDir = Join-Path $ReviewBase "lead-$actualLeadId-$timestamp"
                        if (-not (Test-Path $renamedReviewDir)) {
                            Move-Item -LiteralPath $reviewDir -Destination $renamedReviewDir
                            $actualReviewDir = $renamedReviewDir
                        }
                    }
                    
                    $successful++
                    $results += @{
                        LeadId = $actualLeadId
                        Status = "Success"
                        ReviewPath = $actualReviewDir
                        Domain = $actualDomain
                        ExpectedLeadId = $run.LeadId
                        ExpectedDomain = $run.Domain
                        LeadMismatch = ($actualLeadId -ne [string]$run.LeadId)
                    }
                    
                    # Cleanup temp
                    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Host "  ARTIFACT MISSING: $($run.LeadId)" -ForegroundColor Red
                    $failed++
                    $results += @{ LeadId = $run.LeadId; Status = "ArtifactMissing"; Domain = $run.Domain }
                }
                
                # Delete run
                Remove-WorkflowRun -RepoName $Repo -WorkflowRunId $run.RunId
                
            } else {
                Write-Host "  DONE: $($run.LeadId) - FAILED ($($status.conclusion))" -ForegroundColor Red
                $failed++
                $results += @{ LeadId = $run.LeadId; Status = "Failed"; Conclusion = $status.conclusion; Domain = $run.Domain }
                
                # Delete failed run
                Remove-WorkflowRun -RepoName $Repo -WorkflowRunId $run.RunId
            }
        }
    }
    
    # Progress
    $completed = $runTracker.Where({$_.Status -ne "Triggered"}).Count
    Write-Host "Progress: $completed / $($leads.Count) completed" -ForegroundColor DarkGray
    
    Start-Sleep -Seconds 10
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BATCH COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total attempted: $($leads.Count)" -ForegroundColor White
Write-Host "  Successful:      $successful" -ForegroundColor Green
Write-Host "  Failed:          $failed" -ForegroundColor Red
Write-Host ""

if ($successful -gt 0) {
    Write-Host "Results in: $ReviewBase\" -ForegroundColor Yellow
    Write-Host "Review before applying with -ApplyChanges flag." -ForegroundColor Yellow
}

# Save results log
$logFile = "ops\audit-batch-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$results | ConvertTo-Json -Depth 3 | Out-File $logFile -Encoding UTF8
Write-Host "Log saved: $logFile" -ForegroundColor DarkGray
