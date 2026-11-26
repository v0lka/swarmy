#Requires -Version 5.1
# Shared demo launcher (defaults to the ShopVault demo): PowerShell twin of
# run.sh (bash). Builds & starts the target via docker compose, waits for
# readiness, runs the swarmy session — the headless driver by default, the
# TUI with --tui — and archives the report into <demo>/reports/<run-id>/
# together with the session.yaml provenance snapshot.
#
# Both launchers drive the shared headless_run.py driver (see README.md in
# this directory).
#
# Usage: ./run.ps1 [--tui] [--keep-up] [DEMO_DIR]
#   --tui | -Tui          open the swarmy TUI instead of running the headless driver
#   --keep-up | -KeepUp   leave the target running after the demo (teardown is skipped)
#   DEMO_DIR              demo directory, absolute or relative to the repository root
#                         (default: demos/shop_vault)
# Environment overrides:
#   GOAL_FILE           operator goal text file (default: <demo>/goal.md)
#   DEADLINE_MINUTES    mission deadline passed to the driver (headless only)
#   WAIT_TIMEOUT_SECS   readiness polling budget (default: 300)
#   BACKEND_URL         backend readiness endpoint (default: ShopVault API)
#   FRONTEND_URL        frontend readiness endpoint (default: ShopVault SPA)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Paths are resolved from the script location: the launcher does not
# depend on the directory it is invoked from.
$ScriptDir = $PSScriptRoot
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $ScriptDir '..\..')).Path
$InvocationDir = (Get-Location).Path

function Fail {
    param([string]$Message)
    [Console]::Error.WriteLine("run.ps1: error: $Message")
    exit 1
}

function Write-Usage {
    Write-Host 'usage: run.ps1 [--tui] [--keep-up] [DEMO_DIR]'
    Write-Host '  --tui | -Tui          open the swarmy TUI instead of the headless driver'
    Write-Host '  --keep-up | -KeepUp   leave the target running after the demo'
    Write-Host '  DEMO_DIR              demo directory (default: demos/shop_vault)'
}

# Both the PowerShell (-Tui) and the GNU (--tui) spelling are accepted so the
# launchers stay copy-paste portable; the bash twin uses the GNU spelling.
$Tui = $false
$KeepUp = $false
$DemoDir = $null
$argList = @($args)
for ($i = 0; $i -lt $argList.Count; $i++) {
    $arg = ([string]$argList[$i]).ToLowerInvariant()
    if ($arg -eq '--tui' -or $arg -eq '-tui') {
        $Tui = $true
    } elseif ($arg -eq '--keep-up' -or $arg -eq '-keepup') {
        $KeepUp = $true
    } elseif ($arg -eq '-h' -or $arg -eq '--help' -or $arg -eq '-?') {
        Write-Usage
        exit 0
    } elseif ($arg.StartsWith('-')) {
        Fail "unknown option: $arg (usage: run.ps1 [--tui] [--keep-up] [DEMO_DIR])"
    } else {
        if ($null -ne $DemoDir) {
            Fail "unexpected argument: $arg (usage: run.ps1 [--tui] [--keep-up] [DEMO_DIR])"
        }
        $DemoDir = [string]$argList[$i]
    }
}

if ([string]::IsNullOrEmpty($DemoDir)) {
    $DemoDir = Join-Path $RepoRoot 'demos/shop_vault'
} elseif (-not [System.IO.Path]::IsPathRooted($DemoDir)) {
    # A relative demo path is resolved against the repo root, not the caller's cwd.
    $DemoDir = Join-Path $RepoRoot $DemoDir
}
if (-not (Test-Path -LiteralPath $DemoDir -PathType Container)) {
    Fail "demo directory not found: $DemoDir"
}

$ComposeFile = Join-Path $DemoDir 'target/docker-compose.yml'
$SessionDir = Join-Path $DemoDir 'session'
$RunLog = Join-Path $DemoDir 'run.log'

function Get-EnvValue {
    param([string]$Name)
    return [Environment]::GetEnvironmentVariable($Name)
}

function Wait-Ready {
    param([string]$Name, [string]$Url, [int]$TimeoutSecs = 300)
    Write-Host "run.ps1: waiting for $Name at $Url (up to $TimeoutSecs s)..."
    $deadline = (Get-Date).AddSeconds($TimeoutSecs)
    while ($true) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Write-Host "run.ps1: $Name is ready."
                return
            }
        } catch {
            # not ready yet - keep polling until the deadline below
        }
        if ((Get-Date) -ge $deadline) {
            Fail "$Name not ready after $TimeoutSecs s: $Url"
        }
        Start-Sleep -Seconds 2
    }
}

$transcriptOpen = $false
$locationPushed = $false
try {
    # Full console log of the run (gitignored; overwritten on every run). The
    # TUI owns the terminal, so only headless runs are transcribed.
    if (-not $Tui) {
        try {
            Start-Transcript -Path $RunLog -Force | Out-Null
            $transcriptOpen = $true
        } catch {
            # the transcript is a convenience only - never fail the run over it
        }
    }

    # --- environment pre-flight (fail fast, before touching docker) ---
    if ([string]::IsNullOrEmpty((Get-EnvValue 'DEEPSEEK_API_KEY'))) {
        Fail 'DEEPSEEK_API_KEY is not set; export it first (see the demo README)'
    }
    if ($null -eq (Get-Command docker -ErrorAction SilentlyContinue)) {
        Fail 'docker CLI not found in PATH'
    }
    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        Fail 'docker compose plugin not available'
    }
    if ($null -eq (Get-Command uv -ErrorAction SilentlyContinue)) {
        Fail 'uv not found in PATH (https://docs.astral.sh/uv/)'
    }

    # The operator goal file is a headless-mode input; the TUI takes the goal
    # from the chat, so it is not required there. A relative GOAL_FILE stays
    # relative to the caller's cwd (resolved before the location change below).
    $goalValue = Get-EnvValue 'GOAL_FILE'
    if ([string]::IsNullOrEmpty($goalValue)) {
        $goalFile = Join-Path $DemoDir 'goal.md'
    } elseif ([System.IO.Path]::IsPathRooted($goalValue)) {
        $goalFile = $goalValue
    } else {
        $goalFile = Join-Path $InvocationDir $goalValue
    }
    if (-not $Tui -and -not (Test-Path -Path $goalFile -PathType Leaf)) {
        Fail "operator goal file is missing or empty: $goalFile (create it; see the demo README)"
    }

    if ((Test-Path -Path $SessionDir -PathType Container) -and
        ((Get-ChildItem -Force -Path $SessionDir | Measure-Object).Count -gt 0)) {
        Fail "session dir already holds a session: $SessionDir (resume with 'uv run swarmy --resume', or remove it for a fresh run)"
    }

    # --- target: build & start (frontend :3000, backend API :3001) ---
    Write-Host "run.ps1: demo directory: $DemoDir"
    Write-Host 'run.ps1: building & starting the target...'
    & docker compose -f $ComposeFile up --build -d
    if ($LASTEXITCODE -ne 0) {
        Fail "docker compose up --build -d failed with exit code $LASTEXITCODE"
    }

    # --- readiness: backend API first, then the frontend ---
    $backendUrl = Get-EnvValue 'BACKEND_URL'
    if ([string]::IsNullOrEmpty($backendUrl)) {
        $backendUrl = 'http://127.0.0.1:3001/api/products'
    }
    $frontendUrl = Get-EnvValue 'FRONTEND_URL'
    if ([string]::IsNullOrEmpty($frontendUrl)) {
        $frontendUrl = 'http://127.0.0.1:3000/'
    }
    $waitValue = Get-EnvValue 'WAIT_TIMEOUT_SECS'
    if ([string]::IsNullOrEmpty($waitValue)) {
        $waitTimeout = 300
    } else {
        $waitTimeout = [int]$waitValue
    }
    Wait-Ready -Name 'backend API' -Url $backendUrl -TimeoutSecs $waitTimeout
    Wait-Ready -Name 'frontend' -Url $frontendUrl -TimeoutSecs $waitTimeout

    # --- session: TUI (--tui) or the headless driver ---
    Push-Location -LiteralPath $RepoRoot
    $locationPushed = $true
    if ($Tui) {
        Write-Host 'run.ps1: starting the swarmy TUI...'
        & uv run --group demo swarmy (Join-Path $DemoDir 'session.yaml') --session-dir $SessionDir
        if ($LASTEXITCODE -ne 0) {
            Fail "the swarmy TUI exited with exit code $LASTEXITCODE"
        }
    } else {
        Write-Host 'run.ps1: starting the headless swarmy session...'
        $driverArgs = @(
            '--demo-dir', $DemoDir,
            '--config', (Join-Path $DemoDir 'session.yaml'),
            '--session-dir', $SessionDir,
            '--goal-file', $goalFile
        )
        $deadlineValue = Get-EnvValue 'DEADLINE_MINUTES'
        if (-not [string]::IsNullOrEmpty($deadlineValue)) {
            $driverArgs += @('--deadline-minutes', $deadlineValue)
        }
        & uv run --group demo python (Join-Path $ScriptDir 'headless_run.py') @driverArgs
        if ($LASTEXITCODE -ne 0) {
            Fail "the swarmy session failed with exit code $LASTEXITCODE"
        }
    }

    # --- archive the report (reports/ is kept; session/ stays uncommitted) ---
    $reportSrc = Join-Path $SessionDir 'report.md'
    if (-not (Test-Path -Path $reportSrc -PathType Leaf)) {
        if ($Tui) {
            Write-Host 'run.ps1: no report.md in the session folder; nothing to archive (generate it in the TUI to keep a copy)'
        } else {
            Fail "the driver exited 0 but no report was written: $reportSrc"
        }
    } else {
        $runId = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
        $runDir = Join-Path (Join-Path $DemoDir 'reports') $runId
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null
        Copy-Item -Path $reportSrc -Destination (Join-Path $runDir 'report.md')
        # Resolved config snapshot written by the session (provenance).
        $snapshot = Join-Path $SessionDir 'session.yaml'
        if (-not (Test-Path -Path $snapshot -PathType Leaf)) {
            $snapshot = Join-Path $DemoDir 'session.yaml'
        }
        Copy-Item -Path $snapshot -Destination (Join-Path $runDir 'session.yaml')
        Write-Host "run.ps1: report archived in $runDir"
    }

    Write-Host 'run.ps1: done.'
} catch {
    Fail $_.Exception.Message
} finally {
    if ($locationPushed) {
        Pop-Location
    }
    if ($KeepUp) {
        Write-Host "run.ps1: keeping the target up (-KeepUp); stop it later with: docker compose -f $ComposeFile down"
    } else {
        Write-Host 'run.ps1: tearing down the target...'
        try {
            & docker compose -f $ComposeFile down --remove-orphans 2>$null
        } catch {
            # teardown must never mask the original failure
        }
    }
    if ($transcriptOpen) {
        try {
            Stop-Transcript | Out-Null
        } catch {
            # transcript teardown is best-effort as well
        }
    }
}
