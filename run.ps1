# Run Compliance Scanner (backend + frontend)
# From project root: .\run.ps1

$root = $PSScriptRoot
Set-Location $root

Write-Host "Starting Backend at http://127.0.0.1:8000 ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"

Start-Sleep -Seconds 2
Write-Host "Starting Frontend at http://127.0.0.1:5173 ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\frontend'; npm run dev"

Write-Host ""
Write-Host "Backend:  http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "Frontend: http://127.0.0.1:5173" -ForegroundColor Green
Write-Host "Close the two new windows to stop." -ForegroundColor Yellow
