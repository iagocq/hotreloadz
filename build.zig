const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "hotreloadz",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibC();
    b.installArtifact(exe);

    const example = b.addExecutable(.{
        .name = "example",
        .root_source_file = .{ .path = "example/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const example_dll1 = b.addSharedLibrary(.{
        .name = "original-lib",
        .root_source_file = .{ .path = "example/original-lib.zig" },
        .target = target,
        .optimize = optimize,
    });

    const example_dll2 = b.addSharedLibrary(.{
        .name = "replaced-lib",
        .root_source_file = .{ .path = "example/replaced-lib.zig" },
        .target = target,
        .optimize = optimize,
    });

    example.linkLibC();
    example.linkLibrary(example_dll1);

    b.installArtifact(example);
    b.installArtifact(example_dll1);
    b.installArtifact(example_dll2);
}
