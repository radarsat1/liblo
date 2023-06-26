const std = @import("std");
const Build = std.Build;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "liblo",
        .target = target,
        .optimize = optimize,
    });

    // const pushd = b.addSystemCommand(&.{ "pushd", dir() });
    const configure = b.addSystemCommand(&.{ "cmake", ".", "-DWITH_STATIC=ON" });
    const make = b.addSystemCommand(&.{"make"});
    // const popd = b.addSystemCommand(&.{"popd"});
    make.step.dependOn(&configure.step);
    b.getInstallStep().dependOn(&make.step);
    lib.addObjectFile("liblo.a");

    for (header_files) |file| {
        lib.installHeader(file, file);
    }

    b.installArtifact(lib);
}

// fn dir() []const u8 {
//     return std.fs.path.dirname(@src().file) orelse ".";
// }

const header_files: []const []const u8 = &.{
    "lo/lo_errors.h",
    "lo/lo_lowlevel.h",
    "lo/lo_osc_types.h",
    "lo/lo_macros.h",
    "lo/lo_osc_types.h",
    "lo/lo_throw.h",
    "lo/lo_types.h",
    "lo/lo_serverthread.h",
};

// const src_files = .{
//     "src/address.c",
//     "src/send.c",
//     "src/message.c",
//     "src/method.c",
//     "src/blob.c",
//     "src/bundle.c",
//     "src/timetag.c",
//     "src/pattern_match.c",
//     "src/version.c",
//     "src/server_thread.c",
// };
//
// const config_values = .{
//     .AC_APPLE_UNIVERSAL_BUILD = 0,
//     .ENABLE_IPV6 = 0,
//     .ENABLE_NETWORK_TESTS = 1,
//     .ENABLE_THREADS = 1,
//     .HAVE_DLFCN_H = 1,
//     .HAVE_GETIFADDRS = 1,
//     .HAVE_INET_PTON = 1,
//     .HAVE_LIBM = 0,
//     .HAVE_LIBPTHREAD = 1,
//     .HAVE_NETDB_H = 1,
//     .HAVE_NETINET_IN_H = 1,
//     .HAVE_POLL = 1,
//     .HAVE_SELECT = 1,
//     .HAVE_SETVBUF = 1,
//     .HAVE_STDINT_H = 1,
//     .HAVE_STDIO_H = 1,
//     .HAVE_STDLIB_H = 1,
//     .HAVE_STRINGS_H = 1,
//     .HAVE_STRING_H = 1,
//     .HAVE_SYS_SOCKET_H = 1,
//     .HAVE_SYS_TYPES_H = 1,
//     .HAVE_UINTPTR_T = 1,
//     .HAVE_UNISTD_H = 1,
//     .HAVE_WIN32_THREADS = 0,
//     .LO_BIGENDIAN = "0",
//     .LO_SO_VERSION = "{11, 0, 4}",
//     .LT_OBJDIR = ".libs/",
//     .PACKAGE = "liblo",
//     .PACKAGE_BUGREPORT = "liblo-devel@lists.sourceforge.net",
//     .PACKAGE_NAME = "liblo",
//     .PACKAGE_STRING = "liblo 0.30",
//     .PACKAGE_TARNAME = "liblo",
//     .PACKAGE_URL = "",
//     .PACKAGE_VERSION = "0.30",
//     .PRINTF_LL = "ll",
//     .STDC_HEADERS = 1,
//     .WORDS_BIGENDIAN = 1,
//     .HAVE_INTTYPES_H = 1,
//     .HAVE_SYS_STAT_H = 1,
//     .VERSION = "0.30",
//     .size_t = 0,
//     .uintptr_t = 0,
// };
