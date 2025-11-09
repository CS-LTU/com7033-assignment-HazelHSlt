# MongoDB Portable Startup Script
# Starts MongoDB server from the portable installation

Write-Host "Starting MongoDB Server..." -ForegroundColor Green

$mongoPath = Join-Path $PSScriptRoot "bin\mongod.exe"
$dataPath = Join-Path $PSScriptRoot "data"
$logPath = Join-Path $PSScriptRoot "logs\mongod.log"

# Check if mongod.exe exists
if (-not (Test-Path $mongoPath)) {
    Write-Host "ERROR: MongoDB executable not found at $mongoPath" -ForegroundColor Red
    exit 1
}

# Check if data directory exists
if (-not (Test-Path $dataPath)) {
    Write-Host "Creating data directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
}

# Start MongoDB
Write-Host "MongoDB Path: $mongoPath" -ForegroundColor Cyan
Write-Host "Data Path: $dataPath" -ForegroundColor Cyan
Write-Host "Log Path: $logPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting MongoDB on port 27017..." -ForegroundColor Yellow
Write-Host "Keep this window open while using the application!" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop MongoDB" -ForegroundColor Yellow
Write-Host ""

& $mongoPath --dbpath $dataPath --logpath $logPath --port 27017

