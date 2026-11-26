# SPIDER one-command installer for Windows (PowerShell).
#   irm https://raw.githubusercontent.com/Mahdy0000/SPIDER/main/install.ps1 | iex
# Does: checks/installs Python and Ollama (winget), installs SPIDER into its own venv,
# then runs `spider start` (pulls the model, builds the local RAG index, opens the interactive loop).
$ErrorActionPreference = "Stop"
$Repo = "git+https://github.com/Mahdy0000/SPIDER.git"
$Home_ = Join-Path $env:USERPROFILE ".spider"
$Venv = Join-Path $Home_ "venv"

function Refresh-Path { $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User") }
function Have($n) { return [bool](Get-Command $n -ErrorAction SilentlyContinue) }

Write-Host "== SPIDER install ==" -ForegroundColor Cyan
if (-not (Have "winget") -and (-not (Have "python") -or -not (Have "ollama"))) {
  Write-Host "winget not found. Install Python 3.9+ (python.org) and Ollama (ollama.com/download) by hand, then re-run." -ForegroundColor Red; exit 1
}
if (-not (Have "python")) { Write-Host "Installing Python 3.12 ..."; winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements; Refresh-Path }
if (-not (Have "ollama")) { Write-Host "Installing Ollama ..."; winget install -e --id Ollama.Ollama --accept-package-agreements --accept-source-agreements; Refresh-Path }
if (-not (Have "python")) { Write-Host "Python was installed but is not on PATH yet. Open a NEW PowerShell window and re-run this command." -ForegroundColor Yellow; exit 1 }
if (-not (Have "git")) { Write-Host "Git is needed to install from GitHub. Installing ..."; winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements; Refresh-Path }
if (-not (Have "git")) { Write-Host "Git installed but not on PATH yet. Open a NEW PowerShell window and re-run." -ForegroundColor Yellow; exit 1 }

New-Item -ItemType Directory -Force -Path $Home_ | Out-Null
if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) { Write-Host "Creating venv at $Venv"; python -m venv $Venv }
$Py = Join-Path $Venv "Scripts\python.exe"
Write-Host "Installing SPIDER (no third-party dependencies) ..."
& $Py -m pip install --upgrade --quiet pip
& $Py -m pip install --upgrade $Repo
if ($LASTEXITCODE -ne 0) { Write-Host "pip install failed." -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "Installed. Next time, start with:  & `"$Venv\Scripts\spider.exe`" start" -ForegroundColor Green
& $Py -m spider start
