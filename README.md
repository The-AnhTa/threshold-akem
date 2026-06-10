# AuthKEM Comparison Prototype

This repository contains a C++ research prototype for comparing a standard AuthKEM baseline with a threshold AuthKEM scheme based on ML-KEM-512.

The prototype is intended for local experimentation and measurement. It builds a reusable threshold AuthKEM library, unit/integration tests, and an experiment driver for comparing server-side execution time and communication-related metrics.

## Contents

* `CMakeLists.txt` — CMake build definition.
* `include/` — public headers for the prototype library.
* `src/` — implementation of sharing, transcript handling, assistant logic, combiner logic, front-service logic, public logging, ML-KEM adapter code, and baseline AuthKEM code.
* `experiments/` — experiment drivers, including `run_authkem_comparison.cpp`.
* `tests/` — unit and integration tests.
* `build_and_run.ps1` — optional Windows PowerShell helper script for building and running the experiment.

## Requirements

The project requires:

* CMake
* Ninja, or another CMake-supported build backend
* A C++20 compiler
* OpenSSL
* Windows: MSVC is recommended
* Optional: Miniconda/Anaconda for installing OpenSSL, CMake, and Ninja

On Windows, avoid the old conda `m2w64-toolchain`, because it installs an outdated GCC version that does not support C++20. Use MSVC instead.

## Windows Build Instructions

Open a Visual Studio Developer PowerShell. If the shortcut is unavailable, start it manually from normal PowerShell:

```powershell
& "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64
```

Check that MSVC is available:

```powershell
cl
```

Install OpenSSL, CMake, and Ninja into the conda environment if needed:

```powershell
conda create -n akem-build --override-channels -c conda-forge openssl cmake ninja -y
```

or, if the environment already exists:

```powershell
conda install -n akem-build --override-channels -c conda-forge openssl cmake ninja -y
```

Set the OpenSSL root path:

```powershell
$OpenSSLRoot = "...\AppData\Local\miniconda3\envs\akem-build\Library"
```

Check that OpenSSL is installed:

```powershell
Test-Path "$OpenSSLRoot\include\openssl\opensslv.h"
Test-Path "$OpenSSLRoot\lib\libcrypto.lib"
```

Both commands should return `True`.

Configure and build:

```powershell
cd ...\akem-github
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
cmake -S . -B build -G "Ninja" -DOPENSSL_ROOT_DIR="$OpenSSLRoot" -DOPENSSL_USE_STATIC_LIBS=FALSE
cmake --build build --target run_authkem_comparison
```

Before running the executable, add the OpenSSL binary directory to `PATH`:

```powershell
$env:PATH = "$OpenSSLRoot\bin;$env:PATH"
```

Run the experiment:

```powershell
.\build\run_authkem_comparison.exe --n 3 --t 2 --iterations 1000 --output results32.csv
```

## Example Output

A successful run prints a summary like:

```text
Experiment Configuration:
  n (total assistants): 3
  t (threshold): 2
  iterations: 1000

Running standard AuthKEM baseline...
Running threshold AuthKEM scheme...

CSV output written to: results32.csv
```

The CSV file contains the detailed per-iteration measurements.

```

## Notes

This is a research prototype rather than a production implementation. The threshold scheme is expected to be slower than the standard AuthKEM baseline because it performs additional assistant-side and server-side threshold reconstruction work.

Warnings from external ML-KEM code may appear when building with MSVC. These warnings do not necessarily indicate a build failure. The build only fails if CMake or Ninja reports an error.

## Troubleshooting

### CMake cannot find OpenSSL

Pass the OpenSSL root explicitly:

```powershell
cmake -S . -B build -G "Ninja" -DOPENSSL_ROOT_DIR="$OpenSSLRoot" -DOPENSSL_USE_STATIC_LIBS=FALSE
```

### CMake says the compiler does not support C++20

You are probably using the old conda MinGW compiler. Use MSVC through Visual Studio Developer PowerShell.

### Build fails with a Windows `max` macro error

Add the following to `CMakeLists.txt` after the C/C++ standard settings:

```cmake
if(WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
```

Then delete the build directory and configure again.



