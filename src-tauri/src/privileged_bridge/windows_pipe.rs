use std::{
    ffi::{OsStr, c_void},
    io::{self, Read, Write},
    os::windows::ffi::OsStrExt,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
        HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    },
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        WaitNamedPipeW,
    },
};

pub(crate) const WINDOWS_PIPE_PATH: &str = r"\\.\pipe\dnsblackhole-service";
const PIPE_BUFFER_SIZE: u32 = 512 * 1024;
const PIPE_CONNECT_TIMEOUT_MS: u32 = 5_000;
// SYSTEM 和管理员拥有完全控制权；本机交互式用户仅能读写，远程客户端会被管道模式拒绝。
const PIPE_SECURITY_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

pub(crate) struct WindowsPipeStream {
    handle: HANDLE,
    server_end: bool,
}

unsafe impl Send for WindowsPipeStream {}

impl WindowsPipeStream {
    pub(crate) fn connect() -> Result<Self, String> {
        let pipe_name = wide(WINDOWS_PIPE_PATH);
        if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), PIPE_CONNECT_TIMEOUT_MS) } == 0 {
            return Err(format!(
                "Windows DNS 后台服务尚未就绪：{}",
                io::Error::last_os_error()
            ));
        }
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "无法连接 Windows DNS 后台服务：{}",
                io::Error::last_os_error()
            ));
        }
        Ok(Self {
            handle,
            server_end: false,
        })
    }

    pub(crate) fn accept() -> Result<Self, String> {
        let pipe_name = wide(WINDOWS_PIPE_PATH);
        let security_descriptor = SecurityDescriptor::new(PIPE_SECURITY_SDDL)?;
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                &security_attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "创建 Windows 后台服务命名管道失败：{}",
                io::Error::last_os_error()
            ));
        }

        let connected = unsafe { ConnectNamedPipe(handle, ptr::null_mut()) };
        if connected == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(format!("等待 Windows 后台服务客户端失败：{error}"));
            }
        }
        Ok(Self {
            handle,
            server_end: true,
        })
    }

    pub(crate) fn wake_server() {
        let _ = Self::connect();
    }
}

impl Read for WindowsPipeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let requested = buffer.len().min(u32::MAX as usize) as u32;
        let mut read = 0_u32;
        let result = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr(),
                requested,
                &mut read,
                ptr::null_mut(),
            )
        };
        if result != 0 {
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
            Ok(0)
        } else {
            Err(error)
        }
    }
}

impl Write for WindowsPipeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = buffer.len().min(u32::MAX as usize) as u32;
        let mut written = 0_u32;
        let result = unsafe {
            WriteFile(
                self.handle,
                buffer.as_ptr(),
                requested,
                &mut written,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if unsafe { FlushFileBuffers(self.handle) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for WindowsPipeStream {
    fn drop(&mut self) {
        unsafe {
            if self.server_end {
                DisconnectNamedPipe(self.handle);
            }
            CloseHandle(self.handle);
        }
    }
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn new(sddl: &str) -> Result<Self, String> {
        let sddl = wide(sddl);
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            Err(format!(
                "创建 Windows 命名管道安全描述符失败：{}",
                io::Error::last_os_error()
            ))
        } else {
            Ok(Self(descriptor))
        }
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
