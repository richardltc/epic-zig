// Zig's C translator can't parse arm_neon.h; the header only needs NEON
// for inline helpers we don't use (the compiled library still uses it).
#define DISABLENEON 1
#include "roaring/roaring.h"
