<#
.SYNOPSIS
Run audit-lead.js via GitHub Actions with encrypted artifact download

.DESCRIPTION
Triggers the audit-lead workflow on GitHub Actions, waits for completion,
downloads the encrypted artifact, decrypts it locally, and extracts results.

IMPORTANT: By default, results are extracted to a review folder and NOT applied
to your local profile.md files. This prevents accidental overwrites.

Safe workflow:
  1. Run: .\run-audit-gh.ps1 -LeadId "1234" -Domain "example.com"
  2. Review files in: .\audit-review-1234\
  3. When satisfied, apply: .\run-audit-gh.ps1 -LeadId "1234" -Domain "example.com" -ApplyChanges

.PARAMETER LeadId
The lead ID to audit

.PARAMETER Domain
The domain to audit (without https://)

.PARAMETER ProfileRange
Optional profile range (e.g., "3600-3699")

.PARAMETER KeepEncrypted
Keep the encrypted artifact file after extraction

.PARAMETER SelfDelete
Whether to delete the workflow run after completion (default: true)

.PARAMETER ReviewOnly
Just extract to review folder, don't prompt to apply (default behavior)

.PARAMETER ApplyChanges
Apply the reviewed changes to local profile.md files

.EXAMPLE
.\run-audit-gh.ps1 -LeadId "3648" -Domain "iqmotorsports.com"

.EXAMPLE
.\run-audit-gh.ps1 -LeadId "3648" -Domain "iqmotorsports.com" -ProfileRange "3600-3699"

.EXAMPLE
.\run-audit-gh.ps1 -LeadId "3648" -Domain "iqmotorsports.com" -ApplyChanges
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$LeadId,
    
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [string]$ProfileRange = "",
    
    [switch]$KeepEncrypted = $false,
    
    [bool]$SelfDelete = $true,
    
    [switch]$ReviewOnly = $false,
    
    [switch]$ApplyChanges = $false
)

$ErrorActionPreference = "Stop"

# Config
$Repo = "GalToast/website-audit-engine"
$Workflow = "audit-lead.yml"
$KeyFile = "$env:USERPROFILE\.audit-encryption-key"
$OpenSSL = "C:\Program Files\Git\usr\bin\openssl.exe"

# Colors for output
function Write-Step { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "   $msg" -ForegroundColor Green }
function Write-Err { param($msg) Write-Host "   ERROR: $msg" -ForegroundColor Red }

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

        & gh run download $WorkflowRunId --repo $RepoName -D $DestinationDir 2>&1 | Out-Null
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

# Validate prerequisites
Write-Step "Validating prerequisites..."

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Err "GitHub CLI (gh) not found. Install from: https://cli.github.com/"
    exit 1
}

if (-not (Test-Path $KeyFile)) {
    Write-Err "Encryption key not found at: $KeyFile"
    Write-Host "   Run this to generate one: openssl rand -base64 32 > $KeyFile"
    exit 1
}

if (-not (Test-Path $OpenSSL)) {
    Write-Err "OpenSSL not found at: $OpenSSL"
    exit 1
}

# Check GitHub auth
$authStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "Not authenticated with GitHub CLI. Run: gh auth login"
    exit 1
}
Write-Success "GitHub CLI authenticated"

# Check if secret exists
$secrets = gh secret list --repo $Repo 2>&1
if ($secrets -notmatch "AUDIT_ENCRYPTION_KEY") {
    Write-Err "AUDIT_ENCRYPTION_KEY secret not set in repository"
    Write-Host "   Run: gh secret set AUDIT_ENCRYPTION_KEY --repo $Repo < $KeyFile"
    exit 1
}
Write-Success "Encryption key secret configured"

# Build workflow inputs
Write-Step "Triggering workflow for $Domain..."

$triggeredAtUtc = (Get-Date).ToUniversalTime()
$batchToken = "{0}-{1}-{2}" -f $LeadId, ((Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmssfff")), ([guid]::NewGuid().ToString("N").Substring(0, 8))

$workflowArgs = @(
    "workflow", "run", $Workflow,
    "--repo", $Repo,
    "-f", "lead_id=$LeadId",
    "-f", "domain=$Domain",
    "-f", "batch_token=$batchToken"
)

if ($ProfileRange) {
    $workflowArgs += @("-f", "profile_range=$ProfileRange")
}

$triggerOutput = & gh $workflowArgs 2>&1
$triggerExitCode = $LASTEXITCODE

if ($triggerOutput) {
    $triggerOutput | ForEach-Object { Write-Host $_ }
}

if ($triggerExitCode -ne 0) {
    Write-Err "Failed to trigger workflow"
    exit 1
}
Write-Success "Workflow triggered"

# Wait for workflow to start
Write-Step "Waiting for workflow to start..."
Start-Sleep -Seconds 3

$runId = $null
$triggerOutputText = ($triggerOutput | Out-String)
if ($triggerOutputText -match 'actions/runs/(\d+)') {
    $runId = $Matches[1]
} elseif ($triggerOutputText -match 'gh run view (\d+)') {
    $runId = $Matches[1]
}

if ($runId) {
    Write-Success "Found run ID from trigger output: $runId"
}

$maxAttempts = 30
$attempt = 0

while (-not $runId -and $attempt -lt $maxAttempts) {
    $attempt++
    $runs = gh run list --repo $Repo --workflow $Workflow --limit 20 --json databaseId,status,displayTitle,createdAt 2>$null | ConvertFrom-Json

    $candidateRuns = $runs |
        Where-Object { ([datetime]$_.createdAt).ToUniversalTime() -ge $triggeredAtUtc.AddSeconds(-5) } |
        Sort-Object { ([datetime]$_.createdAt).ToUniversalTime() }

    foreach ($candidateRun in @($candidateRuns)) {
        $artifactMeta = Get-RunArtifactMetadata -RepoName $Repo -WorkflowRunId $candidateRun.databaseId
        if (-not $artifactMeta) { continue }
        if ($artifactMeta.LeadId -ne $LeadId) { continue }
        if ($artifactMeta.BatchToken -ne $batchToken) { continue }

        $runId = $candidateRun.databaseId
        break
    }
    
    if (-not $runId) {
        Write-Host "   Waiting... ($attempt/$maxAttempts)"
        Start-Sleep -Seconds 2
    }
}

if (-not $runId) {
    Write-Err "Could not find workflow run for lead $LeadId"
    exit 1
}
Write-Success "Found run ID: $runId"

# Watch workflow progress
Write-Step "Watching workflow progress..."

& gh run watch $runId --repo $Repo --exit-status

if ($LASTEXITCODE -ne 0) {
    Write-Err "Workflow failed or was cancelled"
    
    # Download logs for debugging
    Write-Host "   Downloading logs for debugging..."
    & gh run view $runId --repo $Repo --log-failed
    
    exit 1
}
Write-Success "Workflow completed successfully"

# Download artifact
Write-Step "Downloading encrypted artifact..."

$downloadDir = ".\audit-temp-$LeadId"
if (Test-Path $downloadDir) {
    Remove-Item -Recurse -Force $downloadDir
}
New-Item -ItemType Directory -Path $downloadDir | Out-Null

$encryptedFile = Get-EncryptedArtifact -RepoName $Repo -WorkflowRunId $runId -DestinationDir $downloadDir

if (-not $encryptedFile) {
    Write-Err "Failed to download artifact"
    exit 1
}
Write-Success "Artifact downloaded"

Write-Success "Found encrypted file: $($encryptedFile.Name)"

# Decrypt
Write-Step "Decrypting results..."

$decryptedFile = Join-Path $downloadDir "audit-results.tar.gz"

& $OpenSSL enc -aes-256-cbc -d -in $encryptedFile.FullName -out $decryptedFile -pass file:"$KeyFile" -pbkdf2

if ($LASTEXITCODE -ne 0) {
    Write-Err "Decryption failed. Check your encryption key."
    exit 1
}
Write-Success "Decrypted successfully"

# Extract
Write-Step "Extracting results..."

# Always extract to review folder first (never overwrite directly)
$reviewDir = ".\audit-review-$LeadId"
if (Test-Path $reviewDir) {
    Remove-Item -Recurse -Force $reviewDir
}
New-Item -ItemType Directory -Path $reviewDir | Out-Null

# Extract tarball to review folder
tar -xzf $decryptedFile -C $reviewDir

if ($LASTEXITCODE -ne 0) {
    Write-Err "Extraction failed"
    exit 1
}
Write-Success "Extracted to review folder: $reviewDir"

# Show what was extracted
Write-Host ""
Write-Host "=== EXTRACTED FILES ===" -ForegroundColor Yellow
Get-ChildItem -Path $reviewDir -Recurse -File | ForEach-Object {
    $relativePath = $_.FullName.Replace("$reviewDir\", "")
    Write-Host "   $relativePath" -ForegroundColor Gray
}

# Check for profile.md changes
$extractedProfile = Get-ChildItem -Path $reviewDir -Recurse -Filter "profile.md" |
    Where-Object { $_.FullName -match [regex]::Escape("\$LeadId-") } |
    Select-Object -First 1
$existingProfile = $null

if ($extractedProfile) {
    # Find existing profile to compare
    $existingProfile = Get-ChildItem -Path "leads\profiles" -Recurse -Filter "profile.md" | 
        Where-Object { $_.FullName -match "\\$LeadId-" } | Select-Object -First 1
}

if ($ReviewOnly -and -not $ApplyChanges) {
    Write-Host ""
    Write-Host "=== REVIEW MODE ===" -ForegroundColor Yellow
    Write-Host "Results extracted to: $reviewDir"
    Write-Host ""
    Write-Host "Files are NOT applied to your local profiles."
    Write-Host "Review the files above, then re-run with -ApplyChanges to apply."
    Write-Host ""
    Write-Host "To apply changes:" -ForegroundColor Cyan
    Write-Host "  .\run-audit-gh.ps1 -LeadId $LeadId -Domain $Domain -ApplyChanges" -ForegroundColor White
    Write-Host ""
    Write-Host "To view profile diff:" -ForegroundColor Cyan
    if ($existingProfile -and $extractedProfile) {
        Write-Host "  git diff --no-index `"$($existingProfile.FullName)`" `"$($extractedProfile.FullName)`"" -ForegroundColor White
    }
    Write-Host ""
    # Skip to cleanup without self-delete so user can re-run
    $SelfDelete = $false
} elseif ($ApplyChanges) {
    Write-Host ""
    Write-Host "=== APPLYING CHANGES ===" -ForegroundColor Yellow
    
    # Copy results to actual locations
    if (Test-Path "$reviewDir\leads\profiles") {
        $leadDirs = Get-ChildItem -Path "$reviewDir\leads\profiles" -Directory -Recurse |
            Where-Object { $_.Name -match "^$LeadId-" }

        foreach ($leadDir in $leadDirs) {
            $rangeName = Split-Path $leadDir.Parent.FullName -Leaf
            $destRangeDir = Join-Path "leads\profiles" $rangeName
            $destLeadDir = Join-Path $destRangeDir $leadDir.Name

            if (-not (Test-Path $destRangeDir)) {
                New-Item -ItemType Directory -Path $destRangeDir -Force | Out-Null
            }

            if (-not (Test-Path $destLeadDir)) {
                New-Item -ItemType Directory -Path $destLeadDir -Force | Out-Null
            }

            Copy-Item -Recurse -Force (Join-Path $leadDir.FullName "*") $destLeadDir
            Write-Success "Updated $rangeName\$($leadDir.Name)"
        }
    }
    
    if (Test-Path "$reviewDir\ops\screenshots") {
        Get-ChildItem -Path "$reviewDir\ops\screenshots" -File -Filter "$LeadId-*" | ForEach-Object {
            Copy-Item -Force $_.FullName "ops\screenshots\"
            Write-Success "Copied screenshot $($_.Name)"
        }
    }
    
    # Copy any JSON files
    Get-ChildItem -Path $reviewDir -Filter "audit-$LeadId*.json" | ForEach-Object {
        Copy-Item -Force $_.FullName "."
        Write-Success "Copied $($_.Name)"
    }
    
    # Clean up review folder after applying
    Remove-Item -Recurse -Force $reviewDir
    Write-Success "Cleaned up review folder"
} else {
    # Default behavior: just show review folder location
    Write-Host ""
    Write-Host "Results extracted to: $reviewDir"
    Write-Host ""
    Write-Host "To apply these changes to your local profiles:" -ForegroundColor Cyan
    Write-Host "  .\run-audit-gh.ps1 -LeadId $LeadId -Domain $Domain -ApplyChanges" -ForegroundColor White
}

# Cleanup
Write-Step "Cleaning up..."

if (-not $KeepEncrypted) {
    Remove-Item -Recurse -Force $downloadDir -ErrorAction SilentlyContinue
    Write-Success "Removed temp files"
}

# Keep review folder unless ApplyChanges was used
if ($ApplyChanges) {
    $reviewDir = ".\audit-review-$LeadId"
    if (Test-Path $reviewDir) {
        Remove-Item -Recurse -Force $reviewDir
    }
}

# Delete workflow run (clears public logs)
if ($SelfDelete) {
    Write-Step "Deleting workflow run..."
    & gh run delete $runId --repo $Repo
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Workflow run deleted (no public trace)"
    } else {
        Write-Host "   Warning: Could not delete workflow run (may still be visible)"
    }
}

# Summary
Write-Step "Done!"
Write-Host ""
Write-Host "   Lead ID:    $LeadId" -ForegroundColor White
Write-Host "   Domain:     $Domain" -ForegroundColor White
if ($ProfileRange) {
    Write-Host "   Profile:    leads\profiles\$ProfileRange\$LeadId-*" -ForegroundColor White
}
Write-Host ""
Write-Host "Results ready for review." -ForegroundColor Green
