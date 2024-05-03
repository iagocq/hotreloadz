const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const str = []const u8;
const wstr = []const u16;
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const kernel32 = windows.kernel32;
const windows_h = @cImport({
    @cInclude("windows.h");
});
const debug = false;

const PROCESSENTRY32W = extern struct {
    dwSize: windows.DWORD,
    cntUsage: windows.DWORD,
    th32ProcessID: windows.DWORD,
    th32DefaultHeapID: windows.ULONG_PTR,
    th32ModuleID: windows.DWORD,
    cntThreads: windows.DWORD,
    th32ParentProcessID: windows.DWORD,
    pcPriClassBase: windows.LONG,
    dwFlags: windows.DWORD,
    szExeFile: [windows.MAX_PATH]windows.WCHAR,
};

const MODULEENTRY32W = extern struct {
    dwSize: windows.DWORD,
    th32ModuleID: windows.DWORD,
    th32ProcessID: windows.DWORD,
    GlblcntUsage: windows.DWORD,
    ProccntUsage: windows.DWORD,
    modBaseAddr: *windows.BYTE,
    modBaseSize: windows.DWORD,
    hModule: windows.HMODULE,
    szModule: [windows.MAX_MODULE_NAME32 + 1]windows.WCHAR,
    szExePath: [windows.MAX_PATH]windows.WCHAR,
};

const DataDirectory = struct { rva: u32, size: u32 };
const PEData = struct { base: usize, version: u32 };

const ExportDirectoryTable = extern struct {
    export_flags: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    name_rva: u32,
    ordinal_base: u32,
    address_table_entries: u32,
    number_of_name_pointers: u32,
    export_address_table_rva: u32,
    name_pointer_rva: u32,
    ordinal_table_rva: u32,
};

extern "kernel32" fn Process32FirstW(hSnapshot: windows.HANDLE, lppe: *PROCESSENTRY32W) callconv(WINAPI) windows.BOOL;
extern "kernel32" fn Process32NextW(hSnapshot: windows.HANDLE, lppe: *PROCESSENTRY32W) callconv(WINAPI) windows.BOOL;
extern "kernel32" fn Module32FirstW(hSnapshot: windows.HANDLE, lpme: *MODULEENTRY32W) callconv(WINAPI) windows.BOOL;
extern "kernel32" fn Module32NextW(hSnapshot: windows.HANDLE, lpme: *MODULEENTRY32W) callconv(WINAPI) windows.BOOL;
extern "kernel32" fn CreateRemoteThread(
    hProcess: windows.HANDLE,
    lpThreadAttributes: *windows.SECURITY_ATTRIBUTES,
    dwStackSize: windows.SIZE_T,
    lpStartAddress: windows.LPTHREAD_START_ROUTINE,
    lpParameter: windows.LPVOID,
    dwCreationFlags: windows.DWORD,
    lpThreadId: *windows.DWORD,
) callconv(WINAPI) windows.HANDLE;

inline fn debug_print_process(alloc: Allocator, process: PROCESSENTRY32W) !void {
    if (debug) {
        const pid = process.th32ProcessID;
        const name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, &process.szExeFile);
        defer alloc.free(name_utf8);

        std.debug.print("{d}\t{s}\n", .{ pid, name_utf8 });
    }
}

inline fn debug_print_module(alloc: Allocator, module: *MODULEENTRY32W) !void {
    if (debug) {
        const exe_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, &module.szExePath);
        const name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, &module.szModule);
        defer alloc.free(exe_utf8);
        defer alloc.free(name_utf8);

        std.debug.print("{s}\t{s}\n", .{ exe_utf8, name_utf8 });
    }
}

pub fn find_process(alloc: Allocator, process_name: str) ![]u32 {
    const snap = kernel32.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0);
    if (snap == windows.INVALID_HANDLE_VALUE) {
        return error.SnapshotFail;
    }
    defer _ = kernel32.CloseHandle(snap);

    const process_name_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(alloc, process_name);
    defer alloc.free(process_name_utf16);

    var pids = std.ArrayList(u32).init(alloc);
    defer pids.deinit();

    var process_entry: PROCESSENTRY32W = undefined;
    process_entry.dwSize = @sizeOf(PROCESSENTRY32W);

    var ok = Process32FirstW(snap, &process_entry);
    while (ok == 1) {
        try debug_print_process(alloc, process_entry);

        var name: []u16 = &process_entry.szExeFile;
        name.len = std.mem.indexOfScalar(u16, name, 0) orelse name.len;

        if (windows.eqlIgnoreCaseWTF16(name, process_name_utf16)) {
            (try pids.addOne()).* = process_entry.th32ProcessID;
        }
        ok = Process32NextW(snap, &process_entry);
    }

    return alloc.dupe(u32, pids.items);
}

fn snapshot_modules(pid: u32) !*anyopaque {
    var snap: *anyopaque = undefined;
    for (0..100) |_| {
        snap = kernel32.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE | windows.TH32CS_SNAPMODULE32, pid);
        if (snap != windows.INVALID_HANDLE_VALUE) break;
        if (kernel32.GetLastError() != .BAD_LENGTH) break;
    }
    if (snap == windows.INVALID_HANDLE_VALUE) {
        return error.SnapshotFail;
    }
    return snap;
}

fn find_module(alloc: Allocator, snap: *anyopaque, module_name: ?str, module: *MODULEENTRY32W) !void {
    module.dwSize = @sizeOf(MODULEENTRY32W);
    var ok = Module32FirstW(snap, module);
    if (module_name == null) {
        if (ok != 1) return error.FailedToFindModule;
        return;
    }

    const full_module_name_utf16 = try std.unicode.utf8ToUtf16LeAlloc(alloc, module_name orelse unreachable);
    const slash_idx = if (std.mem.lastIndexOfAny(u16, full_module_name_utf16, &.{ '\\', '/' })) |idx| idx + 1 else 0;
    const module_name_utf16 = full_module_name_utf16[slash_idx..];

    defer alloc.free(full_module_name_utf16);
    while (ok == 1) {
        try debug_print_module(alloc, module);

        var name: []u16 = &module.szModule;
        name.len = std.mem.indexOfScalar(u16, name, 0) orelse name.len;

        if (windows.eqlIgnoreCaseWTF16(name, module_name_utf16)) {
            return;
        }
        ok = Module32NextW(snap, module);
    }

    return error.FailedToFindModule;
}

fn read_process_memory_slice(hProcess: windows.HANDLE, base: usize, buf: []u8) !void {
    _ = try windows.ReadProcessMemory(hProcess, @ptrFromInt(base), buf);
}

inline fn read_process_memory(hProcess: windows.HANDLE, base: usize, buf: anytype) !void {
    return read_process_memory_slice(hProcess, base, std.mem.asBytes(buf));
}

fn get_pe_data(hProcess: windows.HANDLE, base: usize) !PEData {
    var sig_offset: u16 = undefined;
    try read_process_memory(hProcess, base + 0x3c, &sig_offset);
    var pe_signature: [4]u8 = undefined;
    try read_process_memory(hProcess, base + sig_offset, &pe_signature);
    if (!std.mem.eql(u8, &pe_signature, "PE\x00\x00")) return error.InvalidSignature;
    var pe_magic: u16 = undefined;
    const pe_offset = sig_offset + 4 + 20;
    try read_process_memory(hProcess, base + pe_offset, &pe_magic);
    const pe_version: u32 = switch (pe_magic) {
        0x10b => 32,
        0x20b => 64,
        else => return error.InvalidPEMagic,
    };
    return PEData{ .base = base + pe_offset, .version = pe_version };
}

fn get_export_table_directory(hProcess: windows.HANDLE, pe_data: PEData) !DataDirectory {
    const offset: usize = if (pe_data.version == 32) 96 else 112;
    var export_table_dir: DataDirectory = undefined;
    try read_process_memory(hProcess, pe_data.base + offset, &export_table_dir);
    return export_table_dir;
}

fn get_import_table_directory(hProcess: windows.HANDLE, pe_data: PEData) !DataDirectory {
    const offset: usize = if (pe_data.version == 32) 104 else 120;
    var export_table_dir: DataDirectory = undefined;
    try read_process_memory(hProcess, pe_data.base + offset, &export_table_dir);
    return export_table_dir;
}

fn open_process(pid: u32) !*anyopaque {
    return windows_h.OpenProcess(
        windows_h.PROCESS_CREATE_THREAD //
        | windows_h.PROCESS_QUERY_INFORMATION //
        | windows_h.PROCESS_VM_OPERATION //
        | windows_h.PROCESS_VM_WRITE //
        | windows_h.PROCESS_VM_READ,
        0,
        pid,
    ) orelse error.OpenProcess;
}

pub fn load_lib_into_process(alloc: Allocator, pid: u32, lib: str) !void {
    const hProcess = try open_process(pid);

    var wow64: i32 = 0;
    if (windows_h.IsWow64Process(hProcess, &wow64) == 0) return error.IsWow64Process;
    if (builtin.cpu.arch == .x86_64 and wow64 != 0) return error.UnsupportedProcessArch;
    if (builtin.cpu.arch == .x86 and wow64 == 0) return error.UnsupportedProcessArch;

    const kernel32_utf16 = std.unicode.utf8ToUtf16LeStringLiteral("kernel32");
    const kernel32_mod = kernel32.GetModuleHandleW(kernel32_utf16) orelse return error.Kernel32;
    const LoadLibraryW = kernel32.GetProcAddress(kernel32_mod, "LoadLibraryW") orelse return error.LoadLibraryW;

    const lib_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(alloc, lib);
    defer alloc.free(lib_utf16);

    const lib_name_remote = windows_h.VirtualAllocEx(
        hProcess,
        null,
        lib_utf16.len * @sizeOf(u16),
        windows_h.MEM_COMMIT | windows_h.MEM_RESERVE,
        windows_h.PAGE_READWRITE,
    ) orelse return error.VirtualAlloc;
    defer _ = windows_h.VirtualFreeEx(hProcess, lib_name_remote, 0, windows_h.MEM_FREE);

    _ = try windows.WriteProcessMemory(hProcess, lib_name_remote, std.mem.sliceAsBytes(lib_utf16));

    var thread_id: u32 = undefined;
    const thread = windows_h.CreateRemoteThread(hProcess, null, 0, @ptrCast(LoadLibraryW), lib_name_remote, 0, &thread_id) orelse return error.CreateRemoteThread;
    try windows.WaitForSingleObject(thread, windows.INFINITE);
    var exit_code: u32 = undefined;
    if (windows_h.GetExitCodeThread(thread, &exit_code) == 0) return error.GetExitCode;
    if (exit_code == 0) return error.ExitCode;
}

pub fn hotreload(alloc: Allocator, pid: u32, old_lib_name: str, new_lib_name: str) !void {
    const hProcess = try open_process(pid);

    const snap = try snapshot_modules(pid);
    defer _ = kernel32.CloseHandle(snap);

    var old_lib_module: MODULEENTRY32W = undefined;
    var new_lib_module: MODULEENTRY32W = undefined;

    try find_module(alloc, snap, old_lib_name, &old_lib_module);
    try find_module(alloc, snap, new_lib_name, &new_lib_module);

    // hotreload_ilt(alloc, hProcess, snap, &old_lib_module, &new_lib_module);
    try hotreload_trampoline(alloc, hProcess, snap, &old_lib_module, &new_lib_module);
}

fn hotreload_ilt(alloc: Allocator, hProcess: *anyopaque, snap: *anyopaque, old_lib_module: *MODULEENTRY32W, new_lib_module: *MODULEENTRY32W) !void {
    _ = hProcess; // autofix
    _ = old_lib_module; // autofix
    _ = new_lib_module; // autofix
    var module: MODULEENTRY32W = undefined;
    module.dwSize = @sizeOf(MODULEENTRY32W);
    var ok = Module32FirstW(snap, &module);
    while (ok == 1) {
        try debug_print_module(alloc, &module);

        ok = Module32NextW(snap, &module);
    }
}

const ExportTable = struct {
    name_pointer_table: []align(1) u32,
    export_address_table: []align(1) u32,
    ordinal_table: []align(1) u16,
    bytes: []u8,
    base: usize,
    alloc: ?Allocator = null,

    const Self = @This();

    fn from_process(alloc: Allocator, hProcess: *anyopaque, image_base: usize) !Self {
        const pe_data = try get_pe_data(hProcess, image_base);
        const etd_dd = try get_export_table_directory(hProcess, pe_data);
        const etd = try alloc.alloc(u8, etd_dd.size);
        try read_process_memory_slice(hProcess, image_base + etd_dd.rva, etd);

        var ret = try Self.from_bytes(etd, etd_dd.rva);
        ret.alloc = alloc;

        return ret;
    }

    fn from_bytes(bytes: []u8, rva: usize) !Self {
        const edt: *align(1) ExportDirectoryTable = std.mem.bytesAsValue(ExportDirectoryTable, bytes);

        const n_functions = edt.address_table_entries;
        const n_names = edt.number_of_name_pointers;

        const name_pointer_start = edt.name_pointer_rva - rva;
        const name_pointer_end = name_pointer_start + n_names * @sizeOf(u32);
        const name_pointer_table = std.mem.bytesAsSlice(
            u32,
            bytes[name_pointer_start..name_pointer_end],
        );

        const export_address_start = edt.export_address_table_rva - rva;
        const export_address_end = export_address_start + n_functions * @sizeOf(u32);
        const export_address_table = std.mem.bytesAsSlice(
            u32,
            bytes[export_address_start..export_address_end],
        );

        const ordinal_start = edt.ordinal_table_rva - rva;
        const ordinal_end = ordinal_start + n_names * @sizeOf(u16);
        const ordinal_table = std.mem.bytesAsSlice(
            u16,
            bytes[ordinal_start..ordinal_end],
        );

        return ExportTable{
            .name_pointer_table = name_pointer_table,
            .export_address_table = export_address_table,
            .ordinal_table = ordinal_table,
            .bytes = bytes,
            .base = rva,
        };
    }

    fn get_name_rva(self: *const Self, rva: usize) ?[]u8 {
        if (rva < self.base) return null;

        const addr = rva - self.base;
        const len = std.mem.indexOfScalar(u8, self.bytes[addr..], 0) orelse return null;
        return self.bytes[addr .. addr + len];
    }

    fn get_name_idx(self: *const Self, idx: usize) ?[]u8 {
        if (idx >= self.name_pointer_table.len) return null;

        const rva = self.name_pointer_table[idx];
        return self.get_name_rva(rva);
    }

    fn deinit(self: *const Self) void {
        if (self.alloc) |alloc| {
            alloc.free(self.bytes);
        }
    }
};

inline fn debug_print_trampoline(ord: u16, old_rva: u32, new_rva: u32, name: str) void {
    if (debug) {
        std.debug.print("{d}\t{x}\t{x}\t{s}\n", .{ ord, old_rva, new_rva, name });
    }
}

fn hotreload_trampoline(alloc: Allocator, hProcess: *anyopaque, snap: *anyopaque, old_lib_module: *MODULEENTRY32W, new_lib_module: *MODULEENTRY32W) !void {
    _ = snap; // autofix

    const old_base = @intFromPtr(old_lib_module.modBaseAddr);
    const new_base = @intFromPtr(new_lib_module.modBaseAddr);

    if (old_base == new_base) return error.SameModule;

    const old_et = try ExportTable.from_process(alloc, hProcess, old_base);
    const new_et = try ExportTable.from_process(alloc, hProcess, new_base);
    defer old_et.deinit();
    defer new_et.deinit();

    var old_i: i32 = -1;
    var old_name: ?[]u8 = null;

    for (0..new_et.name_pointer_table.len) |i| blk: {
        const ord = new_et.ordinal_table[i];
        const name = new_et.get_name_idx(i) orelse continue;
        while (old_i == -1 or old_name == null or std.mem.lessThan(u8, old_name.?, name)) {
            old_i += 1;
            if (old_i >= old_et.name_pointer_table.len) break :blk;
            old_name = old_et.get_name_idx(@intCast(old_i));
        }
        if (std.mem.eql(u8, old_name.?, name)) {
            const new_rva = new_et.export_address_table[ord];
            const old_ord = old_et.ordinal_table[@intCast(old_i)];
            const old_rva = old_et.export_address_table[old_ord];

            debug_print_trampoline(ord, old_rva, new_rva, name);
            try write_trampoline(hProcess, old_base + old_rva, new_base + new_rva);
        }
    }
}

fn write_trampoline(hProcess: *anyopaque, where: usize, destination: usize) !void {
    const trampoline_size = 9;
    var old_protection: u32 = undefined;

    // rax is volatile, so we can use it
    var payload: [12]u8 = .{
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, // movabs rax, 0x0000000000000000
        0xff, 0xe0, // jmp rax
    };
    std.mem.writeInt(u64, payload[2..10], destination, .little);

    const ptr: *anyopaque = @ptrFromInt(where);
    if (windows_h.VirtualProtectEx(hProcess, ptr, trampoline_size, windows_h.PAGE_EXECUTE_WRITECOPY, &old_protection) == 0) return error.VirtualProtect;
    defer _ = windows_h.VirtualProtectEx(hProcess, ptr, trampoline_size, old_protection, null);

    _ = try windows.WriteProcessMemory(hProcess, ptr, &payload);
    if (windows_h.FlushInstructionCache(hProcess, ptr, trampoline_size) == 0) return error.FlushInstructionCache;
}

pub fn copy_tmp(alloc: Allocator, lib: str) ![]u8 {
    const dot_idx = std.mem.lastIndexOfScalar(u8, lib, '.') orelse return error.InvalidName;

    var tmp_path_utf16: [windows.MAX_PATH + 2]u16 = undefined;
    const len: usize = windows_h.GetTempPathW(tmp_path_utf16.len, &tmp_path_utf16);
    if (len == 0) return error.GetTempPath;

    const tmp_path = try std.unicode.utf16LeToUtf8Alloc(alloc, tmp_path_utf16[0..len]);
    defer alloc.free(tmp_path);

    const slash_idx = if (std.mem.lastIndexOfAny(u8, lib, &.{ '/', '\\' })) |idx| idx + 1 else 0;
    const t = std.time.timestamp();
    const full_path = try std.fmt.allocPrint(
        alloc,
        "{s}{s}-{d}.dll",
        .{ tmp_path, lib[slash_idx..dot_idx], t },
    );
    std.mem.replaceScalar(u8, full_path, '/', '\\');

    const lib_path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(alloc, lib);
    defer alloc.free(lib_path_utf16);

    const full_path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(alloc, full_path);
    defer alloc.free(full_path_utf16);

    if (windows_h.CopyFileW(lib_path_utf16.ptr, full_path_utf16.ptr, 0) == 0) return error.CopyFile;

    return full_path;
}
