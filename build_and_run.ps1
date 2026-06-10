param(
    [string]$EnvName = "akem-build",
    [switch]$UseMSVC,
    [switch]$Run,
    [string]$RunArgs = "--n 5 --t 3 --iterations 100 --output results.csv"
)

function Write-Heading($msg) {
    Write-Host "==> $msg"
}

Write-Heading "Checking build tools..."

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Write-Error "cmake not found in PATH. Install CMake or enable C++ CMake tools in Visual Studio installer."
    exit 1
}

if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) {
    Write-Error "ninja not found in PATH. Install Ninja or enable C++ CMake tools in Visual Studio installer."
    exit 1
}

if ($UseMSVC) {
    if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
        Write-Error "MSVC compiler 'cl' not found. Run Launch-VsDevShell.ps1 first."
        exit 1
    }

    Write-Heading "Using MSVC compiler:"
    cl 2>&1 | Select-Object -First 1
} else {
    Write-Error "This project requires C++20. The old conda MinGW toolchain is not supported. Please run with -UseMSVC."
    exit 1
}

Write-Heading "Preparing clean build directory..."
if (Test-Path -Path build) {
    Remove-Item -Recurse -Force build
}
New-Item -ItemType Directory -Path build | Out-Null
Set-Location build

Write-Heading "Configuring with MSVC toolchain..."
& cmake -G "Ninja" ..

if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed"
    exit 1
}

Write-Heading "Building target 'run_authkem_comparison'..."
& ninja run_authkem_comparison

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

Write-Heading "Build succeeded. Executable is in $(Get-Location)"

if ($Run) {
    $exe = Join-Path (Get-Location) "run_authkem_comparison.exe"
    if (-not (Test-Path $exe)) {
        Write-Error "Executable not found: $exe"
        exit 1
    }

    Write-Heading "Running experiment: $exe $RunArgs"
    & $exe $RunArgs
}

Write-Heading "Done."