const std = @import("std");
const str = []const u8;
const builtin = @import("builtin");

const process_api = if (builtin.os.tag == .windows) @import("windows.zig") else @panic("unsupported platform");

fn str_eql(a: str, b: str) bool {
    return std.mem.eql(u8, a, b);
}

fn usage(program_name: str) void {
    _ = program_name; // autofix
    std.debug.print("todo usage\n", .{});
}

fn help(program_name: str) void {
    _ = program_name; // autofix
    std.debug.print("todo help\n", .{});
}

pub fn main() u8 {
    wrap() catch |err| {
        const msg = switch (err) {
            else => "TODO handle error",
        };

        std.debug.print("Error: {s}: {s}\n", .{ @errorName(err), msg });
        return @truncate(@intFromError(err));
    };

    return 0;
}

fn next_arg(it: *std.process.ArgIterator) !str {
    return it.next() orelse error.MissingArg;
}

pub fn wrap() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var args_it = try std.process.argsWithAllocator(alloc);
    defer args_it.deinit();

    var args: struct {
        process: ?[]const u8 = null,
        old_lib: ?[]const u8 = null,
        new_lib: ?[]const u8 = null,
        pid: ?u32 = null,
        show_usage: bool = true,
        unknown_arg: bool = false,
        help: bool = false,
    } = .{};

    const program_name = args_it.next() orelse "hotreloadz";

    while (args_it.next()) |arg| {
        if (str_eql(arg, "--process")) {
            args.show_usage = false;
            args.process = try next_arg(&args_it);
        } else if (str_eql(arg, "--old-lib")) {
            args.show_usage = false;
            args.old_lib = try next_arg(&args_it);
        } else if (str_eql(arg, "--new-lib")) {
            args.show_usage = false;
            args.new_lib = try next_arg(&args_it);
        } else if (str_eql(arg, "--pid")) {
            args.show_usage = false;
            args.pid = std.fmt.parseUnsigned(u32, try next_arg(&args_it), 0) catch return error.InvalidPID;
        } else if (str_eql(arg, "--help")) {
            args.help = true;
        } else {
            args.unknown_arg = true;
        }
    }

    if (args.show_usage or args.unknown_arg) {
        usage(program_name);
        return;
    }

    if (args.help) {
        help(program_name);
        return;
    }

    const has_process = args.process != null;
    const has_pid = args.pid != null;
    if (has_pid and has_process or !has_pid and !has_process) {
        return error.EitherProcessOrPID;
    }

    const new_lib = args.new_lib orelse return error.NeedNewLib;
    const old_lib = args.old_lib orelse return error.NeedOldLib;

    var pid: u32 = undefined;

    if (args.pid) |p| {
        pid = p;
    } else if (args.process) |process| {
        const pids = try process_api.find_process(alloc, process);
        defer alloc.free(pids);
        if (pids.len > 1) {
            for (pids) |p| {
                std.debug.print("{d}\n", .{p});
            }
            return error.TooManyProcesses;
        } else if (pids.len == 0) {
            return error.ProcessNotFound;
        }
        pid = pids[0];
    }

    const new_tmp_lib = try process_api.copy_tmp(alloc, new_lib);
    try process_api.load_lib_into_process(alloc, pid, new_tmp_lib);
    try process_api.hotreload(alloc, pid, old_lib, new_tmp_lib);
}
