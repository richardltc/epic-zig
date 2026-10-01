const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // `zig build --release` means ReleaseSafe: runtime safety checks stay on in our code.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    // Release builds drop debug info (much smaller binaries); `-Dstrip=false` keeps it.
    const strip = b.option(bool, "strip", "Strip debug info (default: on for release builds)") orelse (optimize != .Debug);
    // The vendored C/C++ libraries are built fully optimised in any release mode:
    // ReleaseSafe's runtime checks only apply to Zig code anyway.
    const c_optimize: std.builtin.OptimizeMode = if (optimize == .Debug) .Debug else .ReleaseFast;

    const secp_dir = "vendor/rust-secp256k1-zkp/depend/secp256k1-zkp";

    // secp256k1-zkp (MimbleWimble fork): commitments, bulletproofs, aggsig.
    // Flags mirror vendor/rust-secp256k1-zkp/build.rs so results are bit-identical.
    const secp = b.addLibrary(.{
        .name = "secp256k1",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = c_optimize,
            .link_libc = true,
        }),
    });
    secp.root_module.addIncludePath(b.path(secp_dir));
    secp.root_module.addIncludePath(b.path(secp_dir ++ "/include"));
    secp.root_module.addIncludePath(b.path(secp_dir ++ "/src"));
    secp.root_module.addCSourceFiles(.{
        .root = b.path(secp_dir),
        .files = &.{ "src/secp256k1.c", "contrib/lax_der_parsing.c" },
        .flags = &.{
            "-fno-sanitize=undefined",
            "-DUSE_NUM_NONE=1",
            "-DUSE_FIELD_INV_BUILTIN=1",
            "-DUSE_SCALAR_INV_BUILTIN=1",
            "-DUSE_FIELD_10X26=1",
            "-DUSE_SCALAR_8X32=1",
            "-DUSE_ENDOMORPHISM=1",
            "-DENABLE_MODULE_ECDH=1",
            "-DENABLE_MODULE_GENERATOR=1",
            "-DENABLE_MODULE_RECOVERY=1",
            "-DENABLE_MODULE_RANGEPROOF=1",
            "-DENABLE_MODULE_BULLETPROOF=1",
            "-DENABLE_MODULE_AGGSIG=1",
            "-DENABLE_MODULE_SCHNORRSIG=1",
        },
    });

    const roaring = buildRoaring(b, target, c_optimize);
    const randomx = buildRandomX(b, target, c_optimize);
    const rocksdb = buildRocksDB(b, target, c_optimize);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addIncludePath(b.path(secp_dir ++ "/include"));
    test_mod.addIncludePath(b.path("vendor/CRoaring/include"));
    test_mod.addCMacro("CROARING_COMPILER_SUPPORTS_AVX512", "0");
    // translate-c can't parse <stdatomic.h>; refcounts are internal to the library only.
    test_mod.addCMacro("CROARING_ATOMIC_IMPL", "1");
    // ReleaseSafe turns on _FORTIFY_SOURCE, and MinGW's fortified string
    // wrappers don't survive translate-c; our Zig code never calls them.
    if (target.result.os.tag == .windows) test_mod.addCMacro("_FORTIFY_SOURCE", "0");
    test_mod.addIncludePath(b.path("vendor/randomx-rust/randomx/src"));
    test_mod.addIncludePath(b.path("vendor/rocksdb/include"));
    test_mod.linkLibrary(secp);
    test_mod.linkLibrary(roaring);
    test_mod.linkLibrary(randomx);
    test_mod.linkLibrary(rocksdb);
    const test_filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains this") orelse &[0][]const u8{};
    const tests = b.addTest(.{ .root_module = test_mod, .filters = test_filters });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // The node itself.
    const node_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
    });
    node_mod.addImport("epic", test_mod);
    const node = b.addExecutable(.{ .name = "epic-zig", .root_module = node_mod });
    b.installArtifact(node);
    const run_node = b.addRunArtifact(node);
    if (b.args) |args| run_node.addArgs(args);
    const run_step = b.step("run", "Run the node (zig build run -- --data-dir DIR --peer HOST:PORT)");
    run_step.dependOn(&run_node.step);

    // Dev tool: pull real headers/blocks from a node over P2P.
    const fetch_mod = b.createModule(.{
        .root_source_file = b.path("tools/fetch.zig"),
        .target = target,
        .optimize = optimize,
    });
    fetch_mod.addImport("epic", test_mod);
    const fetch = b.addExecutable(.{ .name = "epic-fetch", .root_module = fetch_mod });
    const run_fetch = b.addRunArtifact(fetch);
    if (b.args) |args| run_fetch.addArgs(args);
    const th_mod = b.createModule(.{
        .root_source_file = b.path("tools/txhashset.zig"),
        .target = target,
        .optimize = optimize,
    });
    th_mod.addImport("epic", test_mod);
    const th_exe = b.addExecutable(.{ .name = "epic-txhashset", .root_module = th_mod });
    const run_th = b.addRunArtifact(th_exe);
    if (b.args) |args| run_th.addArgs(args);
    const th_step = b.step("txhashset", "Download a txhashset archive and check roots against the real header");
    th_step.dependOn(&run_th.step);
    const probe_mod = b.createModule(.{
        .root_source_file = b.path("tools/probe.zig"),
        .target = target,
        .optimize = optimize,
    });
    probe_mod.addImport("epic", test_mod);
    const probe_exe = b.addExecutable(.{ .name = "epic-probe", .root_module = probe_mod });
    const run_probe = b.addRunArtifact(probe_exe);
    if (b.args) |args| run_probe.addArgs(args);
    const probe_step = b.step("probe", "Check ping, peer addrs, headers and compact blocks against a node");
    probe_step.dependOn(&run_probe.step);
    const pt_mod = b.createModule(.{
        .root_source_file = b.path("tools/peertest.zig"),
        .target = target,
        .optimize = optimize,
    });
    pt_mod.addImport("epic", test_mod);
    const pt_exe = b.addExecutable(.{ .name = "epic-peertest", .root_module = pt_mod });
    const run_pt = b.addRunArtifact(pt_exe);
    if (b.args) |args| run_pt.addArgs(args);
    const pt_step = b.step("peertest", "Misbehave on purpose against a node (garbage|silent|idle|keepalive)");
    pt_step.dependOn(&run_pt.step);
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("tools/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("epic", test_mod);
    const bench_exe = b.addExecutable(.{ .name = "epic-bench", .root_module = bench_mod });
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Time PoW verification per algorithm");
    bench_step.dependOn(&run_bench.step);
    const cp_mod = b.createModule(.{
        .root_source_file = b.path("tools/checkpoints.zig"),
        .target = target,
        .optimize = optimize,
    });
    cp_mod.addImport("epic", test_mod);
    const cp_exe = b.addExecutable(.{ .name = "epic-checkpoints", .root_module = cp_mod });
    const run_cp = b.addRunArtifact(cp_exe);
    if (b.args) |args| run_cp.addArgs(args);
    const cp_step = b.step("checkpoints", "Print header hashes at given heights from a node");
    cp_step.dependOn(&run_cp.step);
    const kh_mod = b.createModule(.{
        .root_source_file = b.path("tools/kernelhist.zig"),
        .target = target,
        .optimize = optimize,
    });
    kh_mod.addImport("epic", test_mod);
    const kh_exe = b.addExecutable(.{ .name = "epic-kernelhist", .root_module = kh_mod });
    const run_kh = b.addRunArtifact(kh_exe);
    if (b.args) |args| run_kh.addArgs(args);
    const kh_step = b.step("kernelhist", "Time kernel history validation on a synced data dir");
    kh_step.dependOn(&run_kh.step);
    const compact_mod = b.createModule(.{
        .root_source_file = b.path("tools/compact.zig"),
        .target = target,
        .optimize = optimize,
    });
    compact_mod.addImport("epic", test_mod);
    const compact_exe = b.addExecutable(.{ .name = "epic-compact", .root_module = compact_mod });
    const run_compact = b.addRunArtifact(compact_exe);
    if (b.args) |args| run_compact.addArgs(args);
    const compact_step = b.step("compact", "Compact a data dir with a chosen horizon and check the result");
    compact_step.dependOn(&run_compact.step);
    const ps_mod = b.createModule(.{
        .root_source_file = b.path("tools/peerscan.zig"),
        .target = target,
        .optimize = optimize,
    });
    ps_mod.addImport("epic", test_mod);
    const ps_exe = b.addExecutable(.{ .name = "epic-peerscan", .root_module = ps_mod });
    const run_ps = b.addRunArtifact(ps_exe);
    if (b.args) |args| run_ps.addArgs(args);
    const ps_step = b.step("peerscan", "Check which peers in a list complete a handshake");
    ps_step.dependOn(&run_ps.step);
    const fetch_step = b.step("fetch", "Fetch headers/blocks from a node (zig build fetch -- host:port dir count heights...)");
    fetch_step.dependOn(&run_fetch.step);
}

fn buildRoaring(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "roaring",
        .linkage = .static,
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    lib.root_module.addIncludePath(b.path("vendor/CRoaring/include"));
    lib.root_module.addIncludePath(b.path("vendor/CRoaring/src"));
    lib.root_module.addCSourceFiles(.{
        .root = b.path("vendor/CRoaring/src"),
        .files = &.{
            "array_util.c",     "bitset.c",              "bitset_util.c",
            "isadetection.c",   "memory.c",              "roaring.c",
            "roaring64.c",      "roaring_array.c",       "roaring_priority_queue.c",
            "art/art.c",
            "containers/array.c",           "containers/bitset.c",
            "containers/containers.c",      "containers/convert.c",
            "containers/mixed_andnot.c",    "containers/mixed_equal.c",
            "containers/mixed_intersection.c", "containers/mixed_negation.c",
            "containers/mixed_subset.c",    "containers/mixed_union.c",    "containers/mixed_xor.c",
            "containers/run.c",
        },
        .flags = &.{ "-std=c11", "-DCROARING_COMPILER_SUPPORTS_AVX512=0", "-fno-sanitize=undefined" },
    });
    return lib;
}

fn buildRandomX(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "randomx",
        .linkage = .static,
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true, .link_libcpp = true }),
    });
    const dir = "vendor/randomx-rust/randomx";
    lib.root_module.addIncludePath(b.path(dir ++ "/src"));
    const cpu = target.result.cpu.arch;
    const common = [_][]const u8{
        "aes_hash.cpp",      "argon2_ref.c",                "bytecode_machine.cpp",
        "cpu.cpp",           "dataset.cpp",                 "soft_aes.cpp",
        "virtual_memory.c",  "vm_interpreted.cpp",          "allocator.cpp",
        "assembly_generator_x86.cpp", "instruction.cpp",    "randomx.cpp",
        "superscalar.cpp",   "vm_compiled.cpp",             "vm_interpreted_light.cpp",
        "argon2_core.c",     "blake2_generator.cpp",        "instructions_portable.cpp",
        "reciprocal.c",      "virtual_machine.cpp",         "vm_compiled_light.cpp",
        "blake2/blake2b.c",
    };
    const base_flags: []const []const u8 = if (cpu == .x86_64)
        &.{ "-maes", "-fno-sanitize=undefined" }
    else if (cpu == .aarch64)
        &.{ "-march=armv8-a+crypto", "-fno-sanitize=undefined" }
    else
        &.{"-fno-sanitize=undefined"};
    lib.root_module.addCSourceFiles(.{ .root = b.path(dir ++ "/src"), .files = &common, .flags = base_flags });
    switch (cpu) {
        .x86_64 => {
            lib.root_module.addCSourceFiles(.{
                .root = b.path(dir ++ "/src"),
                .files = &.{ "jit_compiler_x86.cpp", "jit_compiler_x86_static.S" },
                .flags = base_flags,
            });
            lib.root_module.addCSourceFile(.{ .file = b.path(dir ++ "/src/argon2_ssse3.c"), .flags = &.{ "-mssse3", "-fno-sanitize=undefined" } });
            lib.root_module.addCSourceFile(.{ .file = b.path(dir ++ "/src/argon2_avx2.c"), .flags = &.{ "-mavx2", "-fno-sanitize=undefined" } });
        },
        .aarch64 => {
            lib.root_module.addCSourceFiles(.{
                .root = b.path(dir ++ "/src"),
                .files = &.{ "jit_compiler_a64.cpp", "jit_compiler_a64_static.S" },
                .flags = base_flags,
            });
            // without x86 SIMD these compile to the "not available" stubs the dispatcher needs
            lib.root_module.addCSourceFiles(.{ .root = b.path(dir ++ "/src"), .files = &.{ "argon2_ssse3.c", "argon2_avx2.c" }, .flags = base_flags });
        },
        else => lib.root_module.addCSourceFiles(.{ .root = b.path(dir ++ "/src"), .files = &.{ "argon2_ssse3.c", "argon2_avx2.c" }, .flags = base_flags }),
    }
    return lib;
}

fn buildRocksDB(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const srcs = @import("build/rocksdb_sources.zig");
    const lib = b.addLibrary(.{
        .name = "rocksdb",
        .linkage = .static,
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true, .link_libcpp = true }),
    });
    const m = lib.root_module;
    m.addIncludePath(b.path("vendor/rocksdb"));
    m.addIncludePath(b.path("vendor/rocksdb/include"));
    const is_win = target.result.os.tag == .windows;
    var flags: std.ArrayList([]const u8) = .empty;
    flags.appendSlice(b.allocator, &.{
        "-std=c++20",
        "-DROCKSDB_NO_DYNAMIC_EXTENSION",
        "-DROCKSDB_SUPPORT_THREAD_LOCAL",
        "-DROCKSDB_LIB_IO_POSIX",
        "-DNDEBUG",
        "-fno-sanitize=undefined",
        "-Wno-deprecated-declarations",
    }) catch @panic("OOM");
    if (is_win) {
        flags.appendSlice(b.allocator, &.{ "-DOS_WIN", "-DROCKSDB_WINDOWS_UTF8_FILENAMES", "-D_WIN32_WINNT=0x0A00", "-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX" }) catch @panic("OOM");
    } else {
        flags.appendSlice(b.allocator, &.{"-DROCKSDB_PLATFORM_POSIX"}) catch @panic("OOM");
        const os_flag: []const u8 = switch (target.result.os.tag) {
            .macos => "-DOS_MACOSX -DHAVE_FULLFSYNC=1",
            .freebsd => "-DOS_FREEBSD",
            else => "-DOS_LINUX",
        };
        flags.append(b.allocator, os_flag) catch @panic("OOM");
        if (target.result.os.tag == .linux) flags.appendSlice(b.allocator, &.{ "-DROCKSDB_FALLOCATE_PRESENT", "-DROCKSDB_MALLOC_USABLE_SIZE", "-DROCKSDB_PTHREAD_ADAPTIVE_MUTEX", "-DROCKSDB_RANGESYNC_PRESENT", "-DROCKSDB_SCHED_GETCPU_PRESENT" }) catch @panic("OOM");
    }
    m.addCSourceFiles(.{ .root = b.path("vendor/rocksdb"), .files = &srcs.common, .flags = flags.items });
    m.addCSourceFile(.{ .file = b.path("build/build_version.cc"), .flags = flags.items });
    m.addCSourceFiles(.{ .root = b.path("vendor/rocksdb"), .files = if (is_win) &srcs.windows else &srcs.posix, .flags = flags.items });
    if (is_win) {
        // UUIDs (rpcrt4) and path helpers (shlwapi) used by RocksDB's Windows port
        m.linkSystemLibrary("rpcrt4", .{});
        m.linkSystemLibrary("shlwapi", .{});
    }
    return lib;
}

