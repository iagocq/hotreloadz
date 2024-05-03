# hotreloadz

Hot reload DLLs in (almost) any executable.

## Downloading

https://github.com/iagocq/hotreloadz/releases/latest

## Building

Install zig 0.12.0.

Run:
```
zig build
```

Binaries will be available in `zig-out/bin`

## Usage

Replace functions in `old.dll` with functions in `new.dll` in process `game.exe`.
```sh
hotreloadz.exe --process game.exe --old-lib old.dll --new-lib ./path/to/new-dll.dll
```

Replace functions in `old.dll` with functions in `another-new.dll` in process with PID 1234.
```sh
hotreloadz.exe --pid 1234 --old-lib old.dll --new-lib ./path/to/another-new.dll
```

Just load `yet-another-new.dll` without replacing any functions.
```sh
hotreloadz.exe --process game.exe --new-lib yet-another-new.dll
```

Arguments explanations
- `--process IMAGE`: targets a process with the given image name. Returns a list of PIDs if multiple processes share the same name.
- `--pid PID`: targets a process with the given PID.
- `--new-lib PATH`: new library to be loaded. Will be copied to a temporary location before being loaded so the original file is still free.
- `--old-lib IMAGE`: name of the loaded library in the process that will have the corresponding functions in `--new-lib` replaced. If not specified, the new library is only loaded, no replacement occurs.
- Must specify either `--process` or `--pid`.
- Must specify `--new-lib`.

## Example

1. Find `example.exe`, `original-lib.dll`, `replaced-lib.dll` in the build/download folder.
2. Place them in the same folder.
3. Execute `example.exe`. Notice the output of $y = 2x$
4. Execute `hotreloadz.exe --process example.exe --old-lib original-lib.dll --new-lib ./path/to/replaced-lib.dll`. Notice how the output changed to $y = x^2$

## How it works

hotreloadz:
1. loads the DLL in the address space of the target process;
2. finds exported functions of the new library;
3. finds corresponding functions of the old library;
4. writes a trampoline (`jmp newaddress`) in place of the old function.

## Future additions

- [ ] File watcher: keep watching a DLL path for updates to its content and automatically inject the file in the target process.
- [ ] Garbage collector: remove old DLLs from the target process's memory before loading new ones.
- [ ] 32-bit support: needs a new 32-bit trampoline.
- [ ] Linux support: support for hot reloading on Linux.
- [ ] Small function support: write special trampolines for functions that are too small to hold the standard trampoline. Has not been a problem yet because functions seem to be aligned to at least 16 bytes by default, but this is an assumption that can easily be broken and lead to problems.
- [ ] Callback functions: call special functions in the old and new libraries when they're loading and unloading.
- [ ] Import Address Table patching: less destructive than trampolines and works with functions of any size, but only works with DLLs that were imported in import tables of the process (DLL is loaded in process initialization), missing LoadLibrary'ed DLLs. The trampoline approach works with all DLLs, even ones loaded with LoadLibrary.

## Why

I wanted a hot reloader for another project I might work on which requires replacing a DLL in a running program if I don't want to spend 30 seconds to test any changes.
