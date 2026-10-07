//! C API for the C++ bridge, declared in `include/sailfactor_core.h`.

use std::ffi::c_char;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// The core's version as a static, NUL-terminated string; never freed.
#[no_mangle]
pub extern "C" fn sf_core_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn version_is_the_package_version() {
        // SAFETY: sf_core_version returns a pointer to a static C string.
        let version = unsafe { CStr::from_ptr(sf_core_version()) };
        assert_eq!(version.to_str(), Ok(env!("CARGO_PKG_VERSION")));
    }
}
