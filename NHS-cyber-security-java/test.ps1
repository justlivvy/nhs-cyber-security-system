$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $env:TEMP "codex-nhs-java-test-login"
$stdout = Join-Path $build "server.out"
$stderr = Join-Path $build "server.err"
$database = Join-Path $build "logins.csv"
$port = 19090

if (Test-Path $build) {
    Get-ChildItem $build -Force | Remove-Item -Recurse -Force
} else {
    New-Item -ItemType Directory -Path $build | Out-Null
}

Push-Location $root
try {
    javac -d $build src\NhsCyberSecurityApp.java
    $server = Start-Process -FilePath "java" -ArgumentList @("-cp", $build, "NhsCyberSecurityApp", $port, $database) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    try {
        $baseUrl = "http://127.0.0.1:$port"
        $ready = $false

        for ($i = 0; $i -lt 60; $i++) {
            try {
                $homeResponse = Invoke-WebRequest "$baseUrl/" -UseBasicParsing
                $ready = $true
                break
            } catch {
                Start-Sleep -Milliseconds 500
            }
        }

        if (-not $ready) {
            if (Test-Path $stderr) {
                Get-Content $stderr
            }
            throw "Server did not start on port $port"
        }

        if ($homeResponse.Content -notmatch "Staff Login Portal") {
            throw "Home page did not contain the expected title"
        }

        $headers = @{ "Content-Type" = "application/json" }
        $registerBody = @{
            fullName = "Test Nurse"
            role = "Nursing Staff"
            username = "test.nurse"
            password = "Testing123!"
        } | ConvertTo-Json
        $register = Invoke-RestMethod "$baseUrl/api/register" -Method Post -Headers $headers -Body $registerBody
        if ($register.status -ne "success") {
            throw "Registration API did not return success"
        }

        $loginBody = @{
            username = "test.nurse"
            password = "Testing123!"
        } | ConvertTo-Json
        $login = Invoke-RestMethod "$baseUrl/api/login" -Method Post -Headers $headers -Body $loginBody
        if ($login.user -ne "test.nurse") {
            throw "Login API did not return the expected user"
        }

        $biometricBody = @{ username = "test.nurse" } | ConvertTo-Json
        $biometric = Invoke-RestMethod "$baseUrl/api/biometric" -Method Post -Headers $headers -Body $biometricBody
        if ($biometric.status -ne "success") {
            throw "Biometric API did not link to the staff login"
        }

        $logs = Invoke-RestMethod "$baseUrl/api/logs"
        if ($logs.logs.Count -lt 4) {
            throw "Server logs did not record the API actions"
        }

        $database = Invoke-RestMethod "$baseUrl/api/database"
        $testUser = $database.users | Where-Object { $_.username -eq "test.nurse" }
        if (-not $testUser) {
            throw "Database endpoint did not return the new staff login"
        }
        if ($testUser.passwordHash -eq "Testing123!") {
            throw "Database exposed a plain-text password"
        }

        $legacy = Invoke-RestMethod "$baseUrl/api/legacy-breach"
        if ($legacy.users.Count -ne 2) {
            throw "Legacy breach endpoint did not return the expected mock users"
        }

        Write-Output "All tests passed."
    } finally {
        if ($server) {
            Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        }
        Get-CimInstance Win32_Process |
            Where-Object { $_.CommandLine -like "*NhsCyberSecurityApp $port*" } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
} finally {
    Pop-Location
}
