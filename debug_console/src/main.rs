extern crate winapi;
extern crate kernel32;

use winapi::winerror;
use std::error::Error;
use winapi::minwinbase::OVERLAPPED;
use std::fs::File;
use std::io::Write;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

/// Convert a Rust utf-8 string to a null terminated utf-16 string
fn win32_string(string: &str) -> Vec<u16>
{
    OsStr::new(string).encode_wide().chain(std::iter::once(0)).collect()
}

struct OverlappedReader {
    filename:    Vec<u16>,
    fd:          Option<std::fs::File>,
    active_read: Option<(OVERLAPPED, Vec<u8>)>,
}

impl OverlappedReader {
    /// Create a new overlapped reader. No file is opened when this is created
    fn new(filename: &str) -> OverlappedReader
    {
        OverlappedReader {
            filename:    win32_string(filename),
            fd:          None,
            active_read: None,
        }
    }

    /// Internal routine to open the file. This is called whenever self.fd
    /// is None, and a handle is needed.
    fn open(&mut self) -> Result<(), String>
    {
        let fd = unsafe {
            /* Attempt to open a new overlapped file */
            let handle = kernel32::CreateFileW(
                self.filename.as_ptr(),
                winapi::winnt::GENERIC_READ | winapi::winnt::GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                winapi::fileapi::OPEN_EXISTING,
                winapi::winbase::FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut());

            /* If we failed, return error */
            if handle == winapi::shlobj::INVALID_HANDLE_VALUE {
                return Err(format!("Failed to create file (error: {})",
                    kernel32::GetLastError()));
            }

            print!("Opened handle {:p}\n", handle);

            File::from_raw_handle(handle) 
        };

        print!("\n=================================\n");
        print!("New serial session\n");
        print!("=================================\n\n");

        /* Set new fd */
        self.fd = Some(fd);
        Ok(())
    }

    /// Do a blocking write of bytes to this file if it is open
    fn write(&mut self, data: &[u8]) -> Result<(), Box<Error>>
    {
        if let Some(ref mut fd) = self.fd {
            fd.write_all(data)?;
            Ok(())
        } else {
            Err("No open fd".into())
        }
    }

    /// Attempt to read `size` bytes. Returns None on error or no bytes
    /// available. Otherwise returns a Vec<u8> containing up to `size` bytes
    /// read.
    fn try_read(&mut self, size: usize) -> Option<Vec<u8>>
    {
        /* If no file is open, try to open it */
        if self.fd.is_none() {
            /* If we failed to open the file return None */
            if self.open().is_err() {
                return None;
            }
        }

        /* At this point either the file was already open or we just opened
         * it. Get the fd.
         */
        let fd = self.fd.as_ref().unwrap().as_raw_handle();

        /* If there is an existing reader */
        if self.active_read.is_some() {
            let (ret, gle, bread) = {
                /* Get a reference to the active read state */
                let ar = self.active_read.as_mut().unwrap();

                /* Cannot read a different size than what is already active */
                assert!(ar.1.len() == size);

                let mut bread = 0u32;
                unsafe {
                    (kernel32::GetOverlappedResult(
                        fd,
                        &mut ar.0,
                        &mut bread,
                        0) == winapi::minwindef::TRUE,
                     kernel32::GetLastError(), bread)
                }
            };

            if !ret || (ret && bread <= 0) {
                /* If the error was not due to the IO not being complete,
                 * free the fd.
                 */
                if (ret && bread <= 0) || gle != winerror::ERROR_IO_INCOMPLETE {
                    self.fd          = None;
                    self.active_read = None;
                }

                None
            } else {
                /* Return buffer, sliced down to bread bytes */
                let mut ret = self.active_read.take().unwrap().1;
                ret.truncate(bread as usize);
                Some(ret)
            }
        } else {
            self.active_read = Some((
                unsafe { std::mem::zeroed() },
                vec![0u8; size]
            ));

            let ret = {
                let ar = self.active_read.as_mut().unwrap();

                /* Schedule a read to the file */
                unsafe {
                    kernel32::ReadFile(
                        fd,
                        ar.1.as_mut_ptr() as *mut std::os::raw::c_void,
                        size as u32,
                        std::ptr::null_mut(),
                        &mut ar.0) == winapi::minwindef::TRUE
                }
            };

            if ret {
                /* If read succeeded synchronously, recursively call this
                 * function which will take the GetOverlappedResult() path.
                 */
                self.try_read(size)
            } else {
                /* Validate there was no unexpected error */
                unsafe {
                    assert!(kernel32::GetLastError() ==
                            winerror::ERROR_IO_PENDING);
                }

                None
            }
        }
    }
}

fn handle_pipe()
{
    let mut serial = OverlappedReader::new("\\\\.\\pipe\\kerndebug");
    let mut conin  = OverlappedReader::new("CONIN$");
    
    loop {
        if let Some(inp) = conin.try_read(1024) {
            match std::str::from_utf8(&inp) {
                Ok("reboot\r\n") => {
                    serial.write(b"Z").unwrap();
                }
                _ => {},
            }
        }

        if let Some(woo) = serial.try_read(1) {
            match std::str::from_utf8(&woo) {
                Ok(value) => {
                    print!("{}", value);
                    std::io::stdout().flush().unwrap();
                },
                Err(_) => {},
            }
        } else {
            /* If there was nothing to display, sleep for 1ms. This just allows
             * this loop to sleep if there is nothing to do. If there is a lot
             * of print traffic it will not be sleeping so there will be no
             * delays.
             */
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

fn main()
{
    handle_pipe();
}

