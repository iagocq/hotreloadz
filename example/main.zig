const std = @import("std");

extern fn transform(x: u32) u32;

pub fn main() u8 {
    var i: u32 = 0;
    while (true) {
        std.debug.print("{d} = {d}\n", .{ i, transform(i) });
        std.time.sleep(std.time.ns_per_s / 2);
        i = (i + 1) % 10;
    }
    return 0;
}
