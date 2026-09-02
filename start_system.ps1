# PowerShell startup script for P-006 Risk Scoring Assessment platform
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Starting P-006 Predictive Risk Scoring Assessment System " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# Ensure synthetic dataset exists
if (-not (Test-Path "backend/data/security_events.json")) {
    Write-Host "[*] Generating synthetic security dataset..." -ForegroundColor Yellow
    python backend/data/generate_demo_data.py
}

# Start Backend API Server
Write-Host "[*] Launching Backend API Server on http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Process -FilePath "python" -ArgumentList "-m uvicorn backend.src.api.server:app --host 127.0.0.1 --port 8000" -WindowStyle Normal

Start-Sleep -Seconds 2

# Start Frontend Dev Server
Write-Host "[*] Launching React Dashboard on http://127.0.0.1:5173 ..." -ForegroundColor Green
Start-Process -FilePath "npm" -ArgumentList "run dev -- --host 127.0.0.1 --port 5173" -WorkingDirectory "frontend" -WindowStyle Normal

Write-Host "`n[+] System is running!" -ForegroundColor Cyan
Write-Host "  - Frontend UI:  http://127.0.0.1:5173/" -ForegroundColor White
Write-Host "  - Backend API:  http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
