const std = @import("std");

const Finding = struct {
    severity: u8,
    text: []u8,
};

const FileResult = struct {
    path: []u8,
    kind: []const u8,
    score: i32,
    verdict: []const u8,
    signal_count: usize,
};

const Cli = struct {
    out_path: []u8,
    inputs: std.ArrayList([]u8),
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cli = try parseArgs(allocator);
    defer {
        allocator.free(cli.out_path);
        for (cli.inputs.items) |p| allocator.free(p);
        cli.inputs.deinit(allocator);
    }

    if (cli.inputs.items.len == 0) {
        printUsage();
        std.process.exit(1);
    }

    try runReport(allocator, cli.out_path, cli.inputs.items);
}

fn printUsage() void {
    std.debug.print("Usage: persistreport [--out report.md] <artifact-file> [more-files...]\n\n", .{});
    std.debug.print("Builds a consolidated persistence triage report from multiple text artifacts.\n", .{});
}

fn parseArgs(allocator: std.mem.Allocator) !Cli {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();

    var out_path = try allocator.dupe(u8, "persistence_report.md");
    errdefer allocator.free(out_path);
    var inputs: std.ArrayList([]u8) = .empty;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        }
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--out")) {
            const value = args.next() orelse return error.MissingOutputPath;
            allocator.free(out_path);
            out_path = try allocator.dupe(u8, value);
            continue;
        }
        try inputs.append(allocator, try allocator.dupe(u8, arg));
    }

    return .{ .out_path = out_path, .inputs = inputs };
}

fn runReport(allocator: std.mem.Allocator, out_path: []const u8, paths: []const []u8) !void {
    var findings: std.ArrayList(Finding) = .empty;
    defer freeFindings(&findings, allocator);

    var files: std.ArrayList(FileResult) = .empty;
    defer freeFileResults(&files, allocator);

    var total_score: i32 = 0;

    for (paths) |path| {
        const data = std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| {
            try addFindingFmt(&findings, allocator, 2, "Failed to read {s}: {s}", .{ path, @errorName(err) });
            continue;
        };
        defer allocator.free(data);

        const kind = detectKind(data);
        const start_idx = findings.items.len;
        const score = try scoreFile(&findings, allocator, path, kind, data);
        const signal_count = findings.items.len - start_idx;
        const verdict = scoreToVerdict(score);

        total_score += score;
        try files.append(allocator, .{
            .path = try allocator.dupe(u8, path),
            .kind = kind,
            .score = score,
            .verdict = verdict,
            .signal_count = signal_count,
        });
    }

    const overall = scoreToVerdict(total_score);
    sortFindings(findings.items);

    try writeMarkdownReport(out_path, files.items, findings.items, total_score, overall);

    std.debug.print("Report written: {s}\n", .{out_path});
    std.debug.print("Files analyzed: {d}\n", .{files.items.len});
    std.debug.print("Overall score: {d} ({s})\n", .{ total_score, overall });
    std.debug.print("Total signals: {d}\n", .{findings.items.len});
}

fn detectKind(data: []const u8) []const u8 {
    if (containsAny(data, &[_][]const u8{ "[hkey_", "windows registry editor", "\\currentversion\\run" })) return "registry";
    if (containsAny(data, &[_][]const u8{ "<task", "<actions>", "<exec>", "<triggers>" })) return "task_xml";
    if (containsAny(data, &[_][]const u8{ "binary_path_name", "service_name", "service_start_name" })) return "service_text";
    if (containsAny(data, &[_][]const u8{ "__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding" })) return "wmi";
    return "generic";
}

fn scoreFile(findings: *std.ArrayList(Finding), allocator: std.mem.Allocator, path: []const u8, kind: []const u8, data: []const u8) !i32 {
    var score: i32 = 0;

    if (std.mem.eql(u8, kind, "registry") and containsAny(data, &[_][]const u8{ "image file execution options", "debugger" })) {
        score += 7;
        try addFindingFmt(findings, allocator, 5, "{s}: IFEO debugger indicator", .{path});
    }

    if (containsAny(data, &[_][]const u8{ "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32" })) {
        score += 5;
        try addFindingFmt(findings, allocator, 4, "{s}: script/LOLBin execution marker", .{path});
    }

    if (containsAny(data, &[_][]const u8{ "-enc", "frombase64string", "iex", "downloadstring" })) {
        score += 5;
        try addFindingFmt(findings, allocator, 5, "{s}: encoded/deobfuscation marker", .{path});
    }

    if (containsAny(data, &[_][]const u8{ "http://", "https://" })) {
        score += 4;
        try addFindingFmt(findings, allocator, 4, "{s}: remote URL reference", .{path});
    }

    if (containsAny(data, &[_][]const u8{ "appdata\\roaming", "\\users\\public\\", "programdata", "temp\\" })) {
        score += 3;
        try addFindingFmt(findings, allocator, 3, "{s}: user-writable execution path", .{path});
    }

    if (std.mem.eql(u8, kind, "task_xml")) {
        if (containsAny(data, &[_][]const u8{ "<hidden>true", "<runlevel>highest" })) {
            score += 3;
            try addFindingFmt(findings, allocator, 3, "{s}: elevated/hidden scheduled task setting", .{path});
        }
        if (containsAny(data, &[_][]const u8{ "<boottrigger", "<logontrigger" })) {
            score += 2;
            try addFindingFmt(findings, allocator, 2, "{s}: boot/logon trigger", .{path});
        }
    }

    if (std.mem.eql(u8, kind, "service_text") and containsAny(data, &[_][]const u8{ "auto_start", "start_type : 2", "start= auto" })) {
        score += 2;
        try addFindingFmt(findings, allocator, 2, "{s}: auto-start service", .{path});
    }

    if (std.mem.eql(u8, kind, "wmi")) {
        if (containsAny(data, &[_][]const u8{ "__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding" })) {
            score += 4;
            try addFindingFmt(findings, allocator, 4, "{s}: WMI persistence component triad", .{path});
        }
        if (containsAny(data, &[_][]const u8{ "win32_processstarttrace", "__instancecreationevent" })) {
            score += 2;
            try addFindingFmt(findings, allocator, 2, "{s}: startup/process event trigger", .{path});
        }
    }

    return score;
}

fn scoreToVerdict(score: i32) []const u8 {
    if (score >= 20) return "HIGH";
    if (score >= 10) return "MEDIUM";
    return "LOW";
}

fn writeMarkdownReport(
    out_path: []const u8,
    files: []const FileResult,
    findings: []const Finding,
    total_score: i32,
    overall: []const u8,
) !void {
    const out = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    defer out.close();

    var wbuf: [4096]u8 = undefined;
    var writer = out.writer(&wbuf);
    const w = &writer.interface;

    try w.print("# Day 30 Persistence Triage Report\n\n", .{});
    try w.print("Overall risk: **{s}**\n", .{overall});
    try w.print("Overall score: **{d}**\n", .{total_score});
    try w.print("Files analyzed: **{d}**\n\n", .{files.len});

    try w.print("## Per-File Summary\n\n", .{});
    try w.print("| File | Kind | Score | Verdict | Signals |\n", .{});
    try w.print("|---|---|---:|---|---:|\n", .{});
    for (files) |fr| {
        try w.print("| {s} | {s} | {d} | {s} | {d} |\n", .{ fr.path, fr.kind, fr.score, fr.verdict, fr.signal_count });
    }

    try w.print("\n## Top Signals\n\n", .{});
    if (findings.len == 0) {
        try w.print("No suspicious signals found.\n", .{});
    } else {
        const max_show = @min(@as(usize, 20), findings.len);
        var i: usize = 0;
        while (i < max_show) : (i += 1) {
            try w.print("- [S{d}] {s}\n", .{ findings[i].severity, findings[i].text });
        }
    }

    try w.flush();
}

fn containsAny(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (containsCi(haystack, needle)) return true;
    }
    return false;
}

fn containsCi(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (asciiEqIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn asciiEqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (std.ascii.toLower(a[i]) != std.ascii.toLower(b[i])) return false;
    }
    return true;
}

fn addFindingFmt(findings: *std.ArrayList(Finding), allocator: std.mem.Allocator, severity: u8, comptime fmt: []const u8, args: anytype) !void {
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    try findings.append(allocator, .{ .severity = severity, .text = msg });
}

fn sortFindings(items: []Finding) void {
    if (items.len < 2) return;
    var i: usize = 0;
    while (i < items.len - 1) : (i += 1) {
        var best_idx = i;
        var j: usize = i + 1;
        while (j < items.len) : (j += 1) {
            if (items[j].severity > items[best_idx].severity) {
                best_idx = j;
            }
        }
        if (best_idx != i) {
            const tmp = items[i];
            items[i] = items[best_idx];
            items[best_idx] = tmp;
        }
    }
}

fn freeFindings(findings: *std.ArrayList(Finding), allocator: std.mem.Allocator) void {
    for (findings.items) |f| allocator.free(f.text);
    findings.deinit(allocator);
}

fn freeFileResults(files: *std.ArrayList(FileResult), allocator: std.mem.Allocator) void {
    for (files.items) |f| allocator.free(f.path);
    files.deinit(allocator);
}
