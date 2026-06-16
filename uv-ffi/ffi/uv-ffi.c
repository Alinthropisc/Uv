/* uv-ffi.c — FFI bridge: version + utility functions */
#include "uv-ffi.h"

#define UV_VERSION_STR "uv/0.1.0 (C23+Rust)"

const char *uv_version(void) {
    return UV_VERSION_STR;
}
