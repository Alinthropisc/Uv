// rawsock.rs — Linux AF_PACKET raw socket abstraction.
// On non-Linux or without root: falls back gracefully (returns error).

use uv_core::error::{UvError, UvResult};

/// Capability guard — checks if raw sockets are available.
/// Type-state pattern: only Privileged can open raw sockets.
pub struct Privileged;
pub struct Unprivileged;

pub struct RawSockGuard<State> {
    _state: std::marker::PhantomData<State>,
}

impl RawSockGuard<Unprivileged> {
    pub fn check() -> Result<RawSockGuard<Privileged>, UvError> {
        #[cfg(unix)]
        {
            // Check effective UID
            let uid = unsafe { libc_getuid() };
            if uid == 0 {
                return Ok(RawSockGuard {
                    _state: std::marker::PhantomData,
                });
            }
            // Also check CAP_NET_RAW via /proc/self/status would go here
        }
        Err(UvError::UnsupportedPlatform(
            "raw sockets require root or CAP_NET_RAW".into(),
        ))
    }
}

impl RawSockGuard<Privileged> {
    /// Open a raw TX socket on the given interface.
    pub fn open_tx(&self, _iface: &str) -> UvResult<RawTx> {
        #[cfg(target_os = "linux")]
        return RawTx::open_linux(_iface);
        #[cfg(not(target_os = "linux"))]
        Err(UvError::UnsupportedPlatform(
            "AF_PACKET only on Linux".into(),
        ))
    }
}

/// Raw transmit socket — wraps the file descriptor.
pub struct RawTx {
    #[cfg(target_os = "linux")]
    fd: i32,
    pub iface: String,
}

impl RawTx {
    #[cfg(target_os = "linux")]
    fn open_linux(iface: &str) -> UvResult<Self> {
        use std::os::raw::c_int;
        // AF_PACKET=17, SOCK_RAW=3, ETH_P_IP=0x0800 htons
        let fd = unsafe { libc_socket(17, 3, (0x0800u16).to_be() as c_int) };
        if fd < 0 {
            return Err(UvError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self {
            fd,
            iface: iface.to_owned(),
        })
    }

    pub fn send(&self, frame: &[u8]) -> UvResult<()> {
        #[cfg(target_os = "linux")]
        {
            let n = unsafe { libc_send(self.fd, frame.as_ptr() as *const _, frame.len(), 0) };
            if n < 0 {
                return Err(UvError::Io(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawTx {
    fn drop(&mut self) {
        unsafe {
            libc_close(self.fd);
        }
    }
}

// Minimal libc stubs to avoid linking libc crate as dep
#[cfg(unix)]
extern "C" {
    fn getuid() -> u32;
}
#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    unsafe { getuid() }
}

#[cfg(target_os = "linux")]
extern "C" {
    fn socket(domain: i32, ty: i32, proto: i32) -> i32;
    fn send(fd: i32, buf: *const std::ffi::c_void, len: usize, flags: i32) -> isize;
    fn close(fd: i32) -> i32;
}
#[cfg(target_os = "linux")]
unsafe fn libc_socket(d: i32, t: i32, p: i32) -> i32 {
    unsafe { socket(d, t, p) }
}
#[cfg(target_os = "linux")]
unsafe fn libc_send(fd: i32, buf: *const std::ffi::c_void, n: usize, f: i32) -> isize {
    unsafe { send(fd, buf, n, f) }
}
#[cfg(target_os = "linux")]
unsafe fn libc_close(fd: i32) {
    unsafe {
        close(fd);
    }
}
