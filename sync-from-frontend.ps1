param(
  [string]$FrontendDir = "..\hotel-frontend"
)

$script = Join-Path $FrontendDir "sync-to-backend.ps1"
if (-not (Test-Path $script)) {
  Write-Error "Expected frontend script at: $script"
  exit 1
}

powershell -ExecutionPolicy Bypass -File $script -BackendDir (Get-Location)
