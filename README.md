# WinAFL EXE Harness

WinAFL harness template/example for fuzzing executables.

For more information, see the associated writeup: <https://debugxp.com/posts/WinAFL_EXE_Fuzzing/>

## Usage

The `WinAFLEXE` folder contains the relevant code for this project. `EXETarget` is an example target, and `Harness` is the harness example.

Inside of the harness code replace `EXE_PATH` with the desired target executable's path.

Modify the harness further as required. This includes, but is not limited to, adding additional setup, loading more dependencies, calling the target's entrypoint, setting up and modifying the `FuzzThis` function as well as the parameters passed to it initially at the end of `main(...)`, and more.

If the harness reports `GetModuleHandleA(...)` error 126 (ERROR_MOD_NOT_FOUND) then the module printed to the terminal must be loaded in `main(...)`. See the commented code for examples.

> Consider building both WinAFL and DynamoRIO yourself to reduce the chances of any issues.

## Example WinAFL Commands

The following PowerShell commands act as a baseline for running and testing the harness.

```powershell
.\drrun.exe `
    -c C:\Dev\Fuzzing\winafl\build64\bin\Release\winafl.dll `
    -debug `
    -target_module Harness.exe `
    -coverage_module EXETarget.exe `
    -target_method FuzzThis `
    -fuzz_iterations 500 `
    -nargs 1 `
    -- `
    "C:\Dev\Fuzzing\WinAFLEXE\x64\Debug\Harness.exe" PATH_TO_SAMPLE_INPUT
```

> Note that with `drrun.exe` do not use `"@@"`.

```powershell
.\afl-fuzz.exe `
    -i C:\Dev\Fuzzing\HeaderParse\afl_in `
    -o C:\Dev\Fuzzing\HeaderParse\Harness\afl_out `
    -t 10000 `
    -D C:\Dev\Fuzzing\DynamoRIO\bin64\ `
    -- `
    -fuzz_iterations 500 `
    -coverage_module EXETarget.exe `
    -target_module Harness.exe `
    -target_method FuzzThis `
    -nargs 1 `
    -- `
    "C:\Dev\Fuzzing\WinAFLEXE\x64\Debug\Harness.exe" "@@"
```

> I had issues with the above and found that using TinyInst resolved the issues. You will have to compile WinAFL with `-DTINYINST=1`.

Running with TinyInst:

```powershell
.\afl-fuzz.exe -y `
    -i C:\Dev\Fuzzing\HeaderParse\afl_in `
    -o C:\Dev\Fuzzing\HeaderParse\Harness\afl_out `
    -t 10000 `
    -D C:\Dev\Fuzzing\dynamorio\build\bin64\ `
    -- `
    -iterations 500 `
    -instrument_module EXETarget.exe `
    -target_module Harness.exe `
    -target_method FuzzThis `
    -nargs 2 `
    -persist `
    -loop `
    -- `
    ""C:\Dev\Fuzzing\WinAFLEXE\x64\Debug\Harness.exe"" "@@"
```

> TinyInst names some parameters differently, as is denoted below.

* `-y` - Specifies the usage of TinyInst. WinAFL must also be compiled with `-DTINYINST=1`.
* `-i` - Input directory with test cases. I chose a couple of small DLLs, namely `dpapi.dll` and `wmi.dll`.
* `-o` - Output directory for fuzzer findings.
* `-t` - Timeout for each run.
* `-D` - Path to DynamoRIO.
* `--` - Instrumentation options begin.
* `-iterations` - Same as `-fuzz_iterations`. How many times to fuzz before restarting the target application.
* `-instrument_module` - Same as `-coverage_module`. Which module to instrument/measure.
* `-target_module` - Module in which the target (see next) resides.
* `-target_method` - Method within the target module which to use as the entrypoint for fuzzing.
* `-nargs` - Number of arguments the target function takes. I'm not sure why this is 2 and not 1, but all of the documentation is like this.
* `-persist` - Speeds up fuzzing by keeping the target alive once the target function returns. This isn't always viable, but in this case it is.
* `-loop` - Causes TinyInst to jump to the start of the target function after it returns.
* `--` - Target commandline begins.
* `""C:\Dev\Fuzzing\WinAFLEXE\x64\Debug\Harness.exe""` - Harness.
* `@@` - Placeholder for WinAFL to fill in the file it's using as input.