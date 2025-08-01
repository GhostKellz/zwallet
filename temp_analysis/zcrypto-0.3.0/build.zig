const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // zcrypto module for library consumers
    const zcrypto_mod = b.addModule("zcrypto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // Main executable (demo)
    const exe = b.addExecutable(.{
        .name = "zcrypto-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    b.installArtifact(exe);

    // Benchmark executable (commented out for now)
    // const bench = b.addExecutable(.{
    //     .name = "zcrypto-bench",
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("src/bench.zig"),
    //         .target = target,
    //         .optimize = .ReleaseFast,
    //         .imports = &.{
    //             .{ .name = "zcrypto", .module = zcrypto_mod },
    //         },
    //     }),
    // });
    // b.installArtifact(bench);

    // Run steps
    const run_step = b.step("run", "Run the demo");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // Benchmark step (disabled for now)
    // const bench_step = b.step("bench", "Run performance benchmarks");
    // const bench_cmd = b.addRunArtifact(bench);
    // bench_cmd.step.dependOn(b.getInstallStep());
    // if (b.args) |args| bench_cmd.addArgs(args);
    // bench_step.dependOn(&bench_cmd.step);

    // Test steps
    const mod_tests = b.addTest(.{
        .root_module = zcrypto_mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
