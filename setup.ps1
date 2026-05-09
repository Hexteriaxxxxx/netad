# NETAD Setup Script — Run this ONCE in PowerShell as Administrator
# Right-click PowerShell -> "Run as Administrator" -> navigate to your project folder -> .\setup.ps1

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  NETAD Security System — Auto Setup" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ── Step 1: Add PostgreSQL to PATH for this session ──
$pgBin = "C:\Program Files\PostgreSQL\18\bin"
if (Test-Path $pgBin) {
    $env:PATH = "$pgBin;$env:PATH"
    Write-Host "[OK] PostgreSQL bin found and added to session PATH." -ForegroundColor Green
} else {
    Write-Host "[ERROR] PostgreSQL bin not found at $pgBin" -ForegroundColor Red
    Write-Host "        Check your PostgreSQL version and update the path in this script." -ForegroundColor Yellow
    exit 1
}

# ── Step 2: Add to system PATH permanently ──
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*PostgreSQL\18\bin*") {
    [System.Environment]::SetEnvironmentVariable(
        "Path",
        "$currentPath;$pgBin",
        "Machine"
    )
    Write-Host "[OK] PostgreSQL added to system PATH permanently." -ForegroundColor Green
} else {
    Write-Host "[OK] PostgreSQL already in system PATH." -ForegroundColor Green
}

# ── Step 3: Prompt for postgres password ──
Write-Host "`nEnter your PostgreSQL password (for user 'postgres'):" -ForegroundColor Yellow
$pgPassword = Read-Host -AsSecureString
$pgPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pgPassword)
)
$env:PGPASSWORD = $pgPasswordPlain

# ── Step 4: Create the netad database if it doesn't exist ──
Write-Host "`n[...] Checking if 'netad' database exists..." -ForegroundColor Cyan
$dbExists = & psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='netad'" 2>$null
if ($dbExists -ne "1") {
    Write-Host "[...] Creating 'netad' database..." -ForegroundColor Cyan
    & psql -U postgres -c "CREATE DATABASE netad;"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Database 'netad' created." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to create database. Check your password and try again." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[OK] Database 'netad' already exists." -ForegroundColor Green
}

# ── Step 5: Run the SQL schema ──
Write-Host "`n[...] Running setup_database.sql..." -ForegroundColor Cyan
$sqlFile = Join-Path $PSScriptRoot "setup_database.sql"
if (-not (Test-Path $sqlFile)) {
    Write-Host "[ERROR] setup_database.sql not found in $PSScriptRoot" -ForegroundColor Red
    exit 1
}
& psql -U postgres -d netad -f $sqlFile
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Database schema applied successfully." -ForegroundColor Green
} else {
    Write-Host "[ERROR] SQL script failed." -ForegroundColor Red
    exit 1
}

# ── Step 6: Install Python dependencies ──
Write-Host "`n[...] Installing Python dependencies..." -ForegroundColor Cyan
$reqFile = Join-Path $PSScriptRoot "requirements.txt"
& pip install -r $reqFile
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Python packages installed." -ForegroundColor Green
} else {
    Write-Host "[WARN] Some packages may have failed. Check output above." -ForegroundColor Yellow
}

# ── Step 7: Check .env ──
Write-Host "`n[...] Checking .env file..." -ForegroundColor Cyan
$envFile = Join-Path $PSScriptRoot ".env"
$envContent = Get-Content $envFile -Raw

$missingKeys = @()
if ($envContent -like "*SECRET_KEY=replace*" -or $envContent -like "*SECRET_KEY=`n*") { $missingKeys += "SECRET_KEY" }
if ($envContent -like "*GROQ_API_KEY=your_groq*") { $missingKeys += "GROQ_API_KEY" }
if ($envContent -like "*PASSWORD_ADMIN=replace*") { $missingKeys += "Passwords (PASSWORD_ADMIN etc)" }
if ($envContent -like "*yourpassword*") { $missingKeys += "DATABASE_URL (still has yourpassword)" }

if ($missingKeys.Count -gt 0) {
    Write-Host "[WARN] These values still need to be filled in your .env:" -ForegroundColor Yellow
    foreach ($k in $missingKeys) {
        Write-Host "       - $k" -ForegroundColor Yellow
    }
    Write-Host "`n       Open .env and fill them in, then run:" -ForegroundColor Yellow
    Write-Host "       python security/generate_keys.py" -ForegroundColor White
} else {
    # ── Step 8: Run generate_keys.py ──
    Write-Host "`n[...] Running generate_keys.py to seed users and generate RSA keys..." -ForegroundColor Cyan
    & python security/generate_keys.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Keys generated and users seeded." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] generate_keys.py failed. Check your .env values." -ForegroundColor Red
    }
}

# ── Done ──
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "  1. Fill in .env if any values above were missing" -ForegroundColor White
Write-Host "  2. Run: python security/generate_keys.py" -ForegroundColor White
Write-Host "  3. Run: python main.py" -ForegroundColor White
Write-Host "  4. Open: http://localhost:5000`n" -ForegroundColor White

# Clear postgres password from environment
$env:PGPASSWORD = ""
