const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zircon = b.dependency("zircon", .{
        .target = target,
        .optimize = optimize,
    });

    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "ircfiber-engine",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{
                    .name = "zircon",
                    .module = zircon.module("zircon"),
                },
                .{
                    .name = "tls",
                    .module = tls_dep.module("tls"),
                },
            },
        }),
    });
    // C helpers
    exe.root_module.addCSourceFile(.{ .file = b.path("src/redis_registration.c") });
    exe.root_module.addCSourceFile(.{ .file = b.path("src/reload_cmsg.c") });
    b.installArtifact(exe);

    // Test target for transport
    const transport_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/transport.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const run_transport_tests = b.addRunArtifact(transport_tests);
    const transport_test_step = b.step("test-transport", "Run transport tests");
    transport_test_step.dependOn(&run_transport_tests.step);

    // Test target for irc parser
    const irc_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/irc.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_irc_tests = b.addRunArtifact(irc_tests);
    const irc_test_step = b.step("test-irc", "Run IRC parser tests");
    irc_test_step.dependOn(&run_irc_tests.step);

    // Test target for reload
    const reload_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/reload.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const run_reload_tests = b.addRunArtifact(reload_tests);
    const reload_test_step = b.step("test-reload", "Run reload tests");
    reload_test_step.dependOn(&run_reload_tests.step);

    // Run all tests
    const all_tests = b.step("test", "Run all tests");
    all_tests.dependOn(&run_transport_tests.step);
    all_tests.dependOn(&run_irc_tests.step);
    all_tests.dependOn(&run_reload_tests.step);
}
