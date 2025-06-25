pub const packages = struct {
    pub const @"TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V";
        pub const build_zig = @import("TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"zledger-0.0.0-gtTGiGb_AAC7uKY-QKTgWw6YhOjusLmSme3vfyJof7Gs" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zledger-0.0.0-gtTGiGb_AAC7uKY-QKTgWw6YhOjusLmSme3vfyJof7Gs";
        pub const build_zig = @import("zledger-0.0.0-gtTGiGb_AAC7uKY-QKTgWw6YhOjusLmSme3vfyJof7Gs");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zledger", "zledger-0.0.0-gtTGiGb_AAC7uKY-QKTgWw6YhOjusLmSme3vfyJof7Gs" },
    .{ "TokioZ", "TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V" },
};
