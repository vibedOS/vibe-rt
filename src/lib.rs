// SPDX-License-Identifier: MIT

#![no_std]

use core::arch::asm;
use core::ffi::{CStr, c_char, c_void};
use core::fmt::{self, Write};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr;
use core::slice;

const SYS_WRITE: usize = 1;
const SYS_READ: usize = 0;
const SYS_CLOSE: usize = 3;
const SYS_DUP2: usize = 33;
const SYS_NANOSLEEP: usize = 35;
const SYS_GETPID: usize = 39;
const SYS_GETUID: usize = 102;
const SYS_GETPPID: usize = 110;
const SYS_SOCKET: usize = 41;
const SYS_CONNECT: usize = 42;
const SYS_ACCEPT: usize = 43;
const SYS_BIND: usize = 49;
const SYS_LISTEN: usize = 50;
const SYS_SETSOCKOPT: usize = 54;
const SYS_FORK: usize = 57;
const SYS_EXECVE: usize = 59;
const SYS_WAIT4: usize = 61;
const SYS_FSYNC: usize = 74;
const SYS_GETCWD: usize = 79;
const SYS_CHDIR: usize = 80;
const SYS_FCHMOD: usize = 91;
const SYS_SYNC: usize = 162;
const SYS_PRCTL: usize = 157;
const SYS_PAUSE: usize = 34;
const SYS_MOUNT: usize = 165;
const SYS_REBOOT: usize = 169;
const SYS_GETDENTS64: usize = 217;
const SYS_EXIT_GROUP: usize = 231;
const SYS_OPENAT: usize = 257;
const SYS_MKDIRAT: usize = 258;
const SYS_UNLINKAT: usize = 263;
const SYS_RENAMEAT: usize = 264;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Errno(pub i32);

pub type Result<T> = core::result::Result<T, Errno>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fork {
    Parent(i32),
    Child,
}

#[derive(Clone, Copy)]
pub struct Args<'a> {
    current: *const *const u8,
    remaining: usize,
    marker: PhantomData<&'a [u8]>,
}

impl<'a> Iterator for Args<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        // SAFETY: Linux supplies argc valid pointers to NUL-terminated argument strings.
        let value = unsafe {
            let pointer = *self.current;
            self.current = self.current.add(1);
            c_bytes(pointer)
        };
        self.remaining -= 1;
        Some(value)
    }
}

#[derive(Clone, Copy)]
pub struct Env<'a> {
    current: *const *const u8,
    marker: PhantomData<&'a [u8]>,
}

impl<'a> Env<'a> {
    pub fn get(mut self, name: &[u8]) -> Option<&'a [u8]> {
        self.find_map(|entry| {
            let separator = entry.iter().position(|byte| *byte == b'=')?;
            (entry[..separator] == *name).then_some(&entry[separator + 1..])
        })
    }
}
impl<'a> Iterator for Env<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: Linux terminates envp with a null pointer.
        let pointer = unsafe { *self.current };
        if pointer.is_null() {
            return None;
        }

        // SAFETY: Each non-null envp entry points to a NUL-terminated string.
        let value = unsafe { c_bytes(pointer) };
        // SAFETY: The null terminator checked above guarantees another pointer slot.
        self.current = unsafe { self.current.add(1) };
        Some(value)
    }
}

#[doc(hidden)]
pub unsafe fn startup<'a>(stack: *const usize) -> (Args<'a>, Env<'a>) {
    // SAFETY: The kernel enters an ELF process with argc at the initial stack pointer.
    let argc = unsafe { *stack };
    // SAFETY: argv begins immediately after argc and has argc entries plus a null.
    let argv = unsafe { stack.add(1).cast::<*const u8>() };
    // SAFETY: envp starts after argv's terminating null.
    let envp = unsafe { argv.add(argc + 1) };

    (
        Args {
            current: argv,
            remaining: argc,
            marker: PhantomData,
        },
        Env {
            current: envp,
            marker: PhantomData,
        },
    )
}

unsafe fn c_bytes<'a>(pointer: *const u8) -> &'a [u8] {
    let mut length = 0;
    // SAFETY: Linux supplies a readable NUL-terminated string.
    while unsafe { pointer.add(length).read_volatile() } != 0 {
        length += 1;
    }
    // SAFETY: The scan above established the readable string length.
    unsafe { slice::from_raw_parts(pointer, length) }
}

#[macro_export]
macro_rules! entry {
    ($main:path) => {
        core::arch::global_asm!(
            ".global _start",
            ".type _start,@function",
            "_start:",
            "xor rbp, rbp",
            "mov rdi, rsp",
            "and rsp, -16",
            "call __vibe_start",
            "ud2",
        );

        #[unsafe(no_mangle)]
        unsafe extern "C" fn __vibe_start(stack: *const usize) -> ! {
            // SAFETY: _start passes the untouched process entry stack pointer.
            let (args, env) = unsafe { $crate::startup(stack) };
            $crate::exit($main(args, env))
        }
    };
}

pub fn write(fd: usize, bytes: &[u8]) -> Result<usize> {
    // SAFETY: bytes supplies a valid readable pointer and length for the syscall.
    decode(unsafe { syscall3(SYS_WRITE, fd, bytes.as_ptr() as usize, bytes.len()) })
}

pub fn read(fd: usize, bytes: &mut [u8]) -> Result<usize> {
    // SAFETY: bytes supplies a valid writable pointer and length for the syscall.
    decode(unsafe { syscall3(SYS_READ, fd, bytes.as_mut_ptr() as usize, bytes.len()) })
}

pub fn write_all(fd: usize, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let written = write(fd, bytes)?;
        if written == 0 {
            return Err(Errno(5));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

const AF_INET: usize = 2;
const SOCK_STREAM: usize = 1;
const SOCK_DGRAM: usize = 2;

#[repr(C)]
struct SocketAddressV4 {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

pub fn tcp_listener(port: u16) -> Result<i32> {
    const SOL_SOCKET: usize = 1;
    const SO_REUSEADDR: usize = 2;

    // SAFETY: socket receives documented integer constants and no pointers.
    let fd = decode(unsafe { syscall3(SYS_SOCKET, AF_INET, SOCK_STREAM, 0) })? as i32;
    let setup = (|| {
        let enabled = 1_i32;
        // SAFETY: enabled points to a readable four-byte socket option.
        decode(unsafe {
            syscall5(
                SYS_SETSOCKOPT,
                fd as usize,
                SOL_SOCKET,
                SO_REUSEADDR,
                (&raw const enabled) as usize,
                size_of::<i32>(),
            )
        })?;

        let address = SocketAddressV4 {
            family: AF_INET as u16,
            port: port.to_be(),
            address: [0; 4],
            zero: [0; 8],
        };
        // SAFETY: address has Linux's sockaddr_in layout and remains live for the call.
        decode(unsafe {
            syscall3(
                SYS_BIND,
                fd as usize,
                (&raw const address) as usize,
                size_of::<SocketAddressV4>(),
            )
        })?;
        // SAFETY: fd is a valid stream socket and 16 is a valid backlog.
        decode(unsafe { syscall2(SYS_LISTEN, fd as usize, 16) })?;
        Ok(())
    })();

    if let Err(error) = setup {
        let _ = close(fd);
        return Err(error);
    }
    Ok(fd)
}

pub fn tcp_connect(address: [u8; 4], port: u16) -> Result<i32> {
    connect_socket(SOCK_STREAM, address, port)
}

pub fn udp_connect(address: [u8; 4], port: u16) -> Result<i32> {
    connect_socket(SOCK_DGRAM, address, port)
}

fn connect_socket(socket_type: usize, address: [u8; 4], port: u16) -> Result<i32> {
    // SAFETY: socket receives documented integer constants and no pointers.
    let fd = decode(unsafe { syscall3(SYS_SOCKET, AF_INET, socket_type, 0) })? as i32;
    let address = SocketAddressV4 {
        family: AF_INET as u16,
        port: port.to_be(),
        address,
        zero: [0; 8],
    };
    // SAFETY: address has Linux's sockaddr_in layout and remains live for the call.
    let connected = decode(unsafe {
        syscall3(
            SYS_CONNECT,
            fd as usize,
            (&raw const address) as usize,
            size_of::<SocketAddressV4>(),
        )
    });
    if let Err(error) = connected {
        let _ = close(fd);
        return Err(error);
    }
    Ok(fd)
}

pub fn accept(listener: i32) -> Result<i32> {
    // SAFETY: Null address pointers request a connection without its peer address.
    decode(unsafe { syscall3(SYS_ACCEPT, listener as usize, 0, 0) }).map(|fd| fd as i32)
}

pub fn set_read_timeout(fd: i32, seconds: u32) -> Result<()> {
    const SOL_SOCKET: usize = 1;
    const SO_RCVTIMEO: usize = 20;

    #[repr(C)]
    struct Timeval {
        seconds: i64,
        microseconds: i64,
    }

    let timeout = Timeval {
        seconds: i64::from(seconds),
        microseconds: 0,
    };
    // SAFETY: timeout has Linux's timeval layout and remains readable for the call.
    decode(unsafe {
        syscall5(
            SYS_SETSOCKOPT,
            fd as usize,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (&raw const timeout) as usize,
            size_of::<Timeval>(),
        )
    })
    .map(|_| ())
}

pub fn close(fd: i32) -> Result<()> {
    // SAFETY: close accepts any integer descriptor and reports invalid ones.
    decode(unsafe { syscall1(SYS_CLOSE, fd as usize) }).map(|_| ())
}

pub fn open_read(path: &CStr) -> Result<i32> {
    const O_RDONLY: usize = 0;
    open(path, O_RDONLY, 0)
}

pub fn open_write(path: &CStr) -> Result<i32> {
    const O_WRONLY: usize = 1;
    const O_CREAT: usize = 0o100;
    const O_TRUNC: usize = 0o1000;
    open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
}

pub fn open_directory(path: &CStr) -> Result<i32> {
    const O_RDONLY: usize = 0;
    const O_DIRECTORY: usize = 0o200000;
    open(path, O_RDONLY | O_DIRECTORY, 0)
}

fn open(path: &CStr, flags: usize, mode: usize) -> Result<i32> {
    const AT_FDCWD: usize = (-100_isize) as usize;
    // SAFETY: path is NUL-terminated and mode is used only when creating a file.
    decode(unsafe { syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as usize, flags, mode) })
        .map(|fd| fd as i32)
}

pub fn duplicate_to(fd: i32, target: i32) -> Result<()> {
    // SAFETY: dup2 validates both integer descriptors.
    decode(unsafe { syscall2(SYS_DUP2, fd as usize, target as usize) }).map(|_| ())
}

pub fn sync_file(fd: i32) -> Result<()> {
    // SAFETY: fsync validates the integer descriptor.
    decode(unsafe { syscall1(SYS_FSYNC, fd as usize) }).map(|_| ())
}

pub fn set_mode(fd: i32, mode: u32) -> Result<()> {
    // SAFETY: fchmod validates the descriptor and mode bits.
    decode(unsafe { syscall2(SYS_FCHMOD, fd as usize, mode as usize) }).map(|_| ())
}

pub fn create_directory(path: &CStr) -> Result<()> {
    const AT_FDCWD: usize = (-100_isize) as usize;
    // SAFETY: path is NUL-terminated and 0755 is a valid directory mode.
    decode(unsafe { syscall3(SYS_MKDIRAT, AT_FDCWD, path.as_ptr() as usize, 0o755) }).map(|_| ())
}

pub fn remove_file(path: &CStr) -> Result<()> {
    unlink(path, 0)
}

pub fn remove_directory(path: &CStr) -> Result<()> {
    const AT_REMOVEDIR: usize = 0x200;
    unlink(path, AT_REMOVEDIR)
}

pub fn rename_file(source: &CStr, target: &CStr) -> Result<()> {
    const AT_FDCWD: usize = (-100_isize) as usize;
    // SAFETY: Both paths are readable NUL-terminated strings.
    decode(unsafe {
        syscall4(
            SYS_RENAMEAT,
            AT_FDCWD,
            source.as_ptr() as usize,
            AT_FDCWD,
            target.as_ptr() as usize,
        )
    })
    .map(|_| ())
}

fn unlink(path: &CStr, flags: usize) -> Result<()> {
    const AT_FDCWD: usize = (-100_isize) as usize;
    // SAFETY: path is NUL-terminated and flags selects file or directory removal.
    decode(unsafe { syscall3(SYS_UNLINKAT, AT_FDCWD, path.as_ptr() as usize, flags) }).map(|_| ())
}

pub fn read_directory(fd: i32, buffer: &mut [u8]) -> Result<usize> {
    // SAFETY: buffer is writable and fd must name an open directory.
    decode(unsafe {
        syscall3(
            SYS_GETDENTS64,
            fd as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
        )
    })
}

pub fn current_dir(buffer: &mut [u8]) -> Result<&[u8]> {
    // SAFETY: buffer is writable for its full length.
    let length =
        decode(unsafe { syscall2(SYS_GETCWD, buffer.as_mut_ptr() as usize, buffer.len()) })?;
    if length == 0 || buffer[length - 1] != 0 {
        return Err(Errno(5));
    }
    Ok(&buffer[..length - 1])
}

pub fn change_dir(path: &CStr) -> Result<()> {
    // SAFETY: path is a readable NUL-terminated string.
    decode(unsafe { syscall1(SYS_CHDIR, path.as_ptr() as usize) }).map(|_| ())
}

#[doc(hidden)]
pub fn print(arguments: fmt::Arguments<'_>, fd: usize) {
    let _ = FdWriter(fd).write_fmt(arguments);
}

#[macro_export]
macro_rules! print {
    ($($argument:tt)*) => {
        $crate::print(core::format_args!($($argument)*), 1)
    };
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print(core::format_args!("\n"), 1)
    };
    ($($argument:tt)*) => {
        $crate::print(core::format_args!("{}\n", core::format_args!($($argument)*)), 1)
    };
}

#[macro_export]
macro_rules! eprintln {
    () => {
        $crate::print(core::format_args!("\n"), 2)
    };
    ($($argument:tt)*) => {
        $crate::print(core::format_args!("{}\n", core::format_args!($($argument)*)), 2)
    };
}

pub fn mount(
    source: Option<&CStr>,
    target: &CStr,
    filesystem: &CStr,
    flags: usize,
    data: Option<&CStr>,
) -> Result<()> {
    let source = source.map_or(ptr::null(), CStr::as_ptr);
    let data = data.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: All pointers are either null or valid NUL-terminated strings.
    decode(unsafe {
        syscall5(
            SYS_MOUNT,
            source as usize,
            target.as_ptr() as usize,
            filesystem.as_ptr() as usize,
            flags,
            data.cast::<c_void>() as usize,
        )
    })
    .map(|_| ())
}

pub fn pause() {
    // SAFETY: pause has no arguments and only waits for a signal.
    unsafe {
        syscall0(SYS_PAUSE);
    }
}

pub fn fork() -> Result<Fork> {
    // SAFETY: fork has no arguments.
    decode(unsafe { syscall0(SYS_FORK) }).map(|pid| {
        if pid == 0 {
            Fork::Child
        } else {
            Fork::Parent(pid as i32)
        }
    })
}

/// Replaces the current process image.
///
/// # Safety
///
/// `argv` and `envp` must point to null-terminated arrays of valid C strings.
pub unsafe fn execve(
    path: &CStr,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Result<()> {
    // SAFETY: The caller guarantees valid, null-terminated argument arrays.
    decode(unsafe {
        syscall3(
            SYS_EXECVE,
            path.as_ptr() as usize,
            argv as usize,
            envp as usize,
        )
    })
    .map(|_| ())
}

pub fn wait_pid(pid: i32) -> Result<i32> {
    let mut status = 0_i32;
    // SAFETY: status points to writable memory and a null rusage is allowed.
    decode(unsafe { syscall4(SYS_WAIT4, pid as usize, (&raw mut status) as usize, 0, 0) })
        .map(|_| status)
}

pub fn wait_any() -> Result<(i32, i32)> {
    let mut status = 0_i32;
    // SAFETY: -1 selects any child; status is writable and a null rusage is allowed.
    decode(unsafe { syscall4(SYS_WAIT4, usize::MAX, (&raw mut status) as usize, 0, 0) })
        .map(|pid| (pid as i32, status))
}

pub fn getpid() -> i32 {
    // SAFETY: getpid has no arguments and cannot fail.
    unsafe { syscall0(SYS_GETPID) as i32 }
}

pub fn getuid() -> u32 {
    // SAFETY: getuid has no arguments and cannot fail.
    unsafe { syscall0(SYS_GETUID) as u32 }
}

pub fn getppid() -> i32 {
    // SAFETY: getppid has no arguments and cannot fail.
    unsafe { syscall0(SYS_GETPPID) as i32 }
}

pub fn terminate_with_parent() -> Result<()> {
    const PR_SET_PDEATHSIG: usize = 1;
    const SIGTERM: usize = 15;
    // SAFETY: prctl documents these constants and ignores the remaining arguments.
    decode(unsafe { syscall5(SYS_PRCTL, PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) }).map(|_| ())
}

pub fn sleep(seconds: i64) {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    let duration = Timespec {
        seconds,
        nanoseconds: 0,
    };
    // SAFETY: duration points to a valid timespec and the remainder is unused.
    unsafe {
        syscall2(SYS_NANOSLEEP, (&raw const duration) as usize, 0);
    }
}

pub fn reboot() -> Result<()> {
    const MAGIC_1: usize = 0xfee1_dead;
    const MAGIC_2: usize = 0x2812_1969;
    const RESTART: usize = 0x0123_4567;

    // SAFETY: sync has no arguments.
    unsafe {
        syscall0(SYS_SYNC);
    }
    // SAFETY: Linux documents these constants for the reboot syscall.
    decode(unsafe { syscall4(SYS_REBOOT, MAGIC_1, MAGIC_2, RESTART, 0) }).map(|_| ())
}

pub fn exit(code: i32) -> ! {
    // SAFETY: exit_group terminates the current process.
    unsafe {
        syscall1(SYS_EXIT_GROUP, code as usize);
        asm!("ud2", options(noreturn));
    }
}

#[doc(hidden)]
#[cfg(all(not(test), not(feature = "hosted")))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

/// Fills `count` bytes at `destination` with `value`.
///
/// # Safety
///
/// `destination` must be valid for writes of `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(destination: *mut c_void, value: i32, count: usize) -> *mut c_void {
    let bytes = destination.cast::<u8>();
    for offset in 0..count {
        // SAFETY: The caller guarantees the full destination range is writable.
        unsafe {
            bytes.add(offset).write_volatile(value as u8);
        }
    }
    destination
}

/// Copies `count` non-overlapping bytes from `source` to `destination`.
///
/// # Safety
///
/// Both ranges must be valid for `count` bytes and must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let destination_bytes = destination.cast::<u8>();
    let source_bytes = source.cast::<u8>();
    for offset in 0..count {
        // SAFETY: The caller guarantees valid, non-overlapping ranges.
        unsafe {
            destination_bytes
                .add(offset)
                .write_volatile(source_bytes.add(offset).read_volatile());
        }
    }
    destination
}

/// Moves `count` bytes from `source` to `destination`, allowing overlap.
///
/// # Safety
///
/// Both ranges must be valid for `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let destination_bytes = destination.cast::<u8>();
    let source_bytes = source.cast::<u8>();
    if (destination_bytes as usize) <= (source_bytes as usize) {
        // SAFETY: memcpy's forward copy is valid when destination precedes source.
        unsafe {
            memcpy(destination, source, count);
        }
    } else {
        for offset in (0..count).rev() {
            // SAFETY: Reverse order preserves bytes for overlapping ranges.
            unsafe {
                destination_bytes
                    .add(offset)
                    .write_volatile(source_bytes.add(offset).read_volatile());
            }
        }
    }
    destination
}

/// Compares two byte ranges lexicographically.
///
/// # Safety
///
/// Both ranges must be readable for `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> i32 {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for offset in 0..count {
        // SAFETY: The caller guarantees both ranges are readable.
        let difference = unsafe {
            i32::from(left.add(offset).read_volatile())
                - i32::from(right.add(offset).read_volatile())
        };
        if difference != 0 {
            return difference;
        }
    }
    0
}

/// Reports whether two byte ranges differ.
///
/// # Safety
///
/// Both ranges must be readable for `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, count: usize) -> i32 {
    // SAFETY: The caller provides the same readable ranges required by memcmp.
    unsafe { memcmp(left, right, count) }
}

/// Returns the length of a NUL-terminated byte string.
///
/// # Safety
///
/// `value` must point to a readable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(value: *const c_char) -> usize {
    let mut length = 0;
    // SAFETY: The caller guarantees a readable string ending in NUL.
    while unsafe { value.add(length).read_volatile() } != 0 {
        length += 1;
    }
    length
}

fn decode(value: isize) -> Result<usize> {
    if value < 0 {
        Err(Errno((-value) as i32))
    } else {
        Ok(value as usize)
    }
}

struct FdWriter(usize);

impl Write for FdWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        write_all(self.0, value.as_bytes()).map_err(|_| fmt::Error)
    }
}

unsafe fn syscall0(number: usize) -> isize {
    let result: isize;
    // SAFETY: The caller supplies a valid Linux x86_64 syscall number.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

unsafe fn syscall1(number: usize, first: usize) -> isize {
    let result: isize;
    // SAFETY: The caller validates the syscall number and argument.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") first,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

unsafe fn syscall2(number: usize, first: usize, second: usize) -> isize {
    let result: isize;
    // SAFETY: The caller validates the syscall number and arguments.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") first,
            in("rsi") second,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

unsafe fn syscall3(number: usize, first: usize, second: usize, third: usize) -> isize {
    let result: isize;
    // SAFETY: The caller validates the syscall number and arguments.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

unsafe fn syscall4(
    number: usize,
    first: usize,
    second: usize,
    third: usize,
    fourth: usize,
) -> isize {
    let result: isize;
    // SAFETY: The caller validates the syscall number and arguments.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            in("r10") fourth,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

unsafe fn syscall5(
    number: usize,
    first: usize,
    second: usize,
    third: usize,
    fourth: usize,
    fifth: usize,
) -> isize {
    let result: isize;
    // SAFETY: The caller validates the syscall number and arguments.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            in("r10") fourth,
            in("r8") fifth,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        bcmp, change_dir, close, create_directory, current_dir, decode, duplicate_to, memcmp,
        memcpy, memmove, memset, open_directory, open_read, open_write, read, read_directory,
        remove_directory, remove_file, rename_file, set_mode, set_read_timeout, strlen, sync_file,
        tcp_connect, tcp_listener, udp_connect, write_all,
    };

    #[test]
    fn decodes_linux_syscall_results() {
        assert_eq!(decode(7), Ok(7));
        assert_eq!(decode(-2), Err(super::Errno(2)));
    }

    #[test]
    fn supplies_compiler_memory_intrinsics() {
        let mut bytes = [0_u8; 6];
        // SAFETY: All pointers reference the local six-byte array.
        unsafe {
            memset(bytes.as_mut_ptr().cast(), 7, bytes.len());
            assert_eq!(bytes, [7; 6]);

            let source = [1_u8, 2, 3];
            memcpy(
                bytes.as_mut_ptr().cast(),
                source.as_ptr().cast(),
                source.len(),
            );
            assert_eq!(bytes, [1, 2, 3, 7, 7, 7]);

            memmove(bytes.as_mut_ptr().add(1).cast(), bytes.as_ptr().cast(), 5);
            assert_eq!(bytes, [1, 1, 2, 3, 7, 7]);

            assert_eq!(memcmp(b"abc".as_ptr().cast(), b"abc".as_ptr().cast(), 3), 0);
            assert!(memcmp(b"abc".as_ptr().cast(), b"abd".as_ptr().cast(), 3) < 0);
            assert_eq!(bcmp(b"abc".as_ptr().cast(), b"abc".as_ptr().cast(), 3), 0);
            assert_ne!(bcmp(b"abc".as_ptr().cast(), b"abd".as_ptr().cast(), 3), 0);

            assert_eq!(strlen(c"vibe".as_ptr()), 4);
        }
    }

    #[test]
    fn opens_a_file_for_reading() {
        let fd = open_read(c"/dev/null").unwrap();
        close(fd).unwrap();
    }

    #[test]
    fn writes_and_removes_a_file() {
        let path = c"/tmp/vibe-rt-write-test";
        let _ = remove_file(path);
        let fd = open_write(path).unwrap();
        write_all(fd as usize, b"vibe").unwrap();
        close(fd).unwrap();

        let fd = open_read(path).unwrap();
        let mut content = [0_u8; 4];
        assert_eq!(read(fd as usize, &mut content), Ok(4));
        assert_eq!(content, *b"vibe");
        close(fd).unwrap();
        remove_file(path).unwrap();
    }

    #[test]
    fn atomically_replaces_a_file() {
        let temporary = c"/tmp/vibe-rt-atomic-test.tmp";
        let installed = c"/tmp/vibe-rt-atomic-test";
        let _ = remove_file(temporary);
        let _ = remove_file(installed);

        let fd = open_write(temporary).unwrap();
        write_all(fd as usize, b"installed").unwrap();
        set_mode(fd, 0o755).unwrap();
        sync_file(fd).unwrap();
        close(fd).unwrap();
        rename_file(temporary, installed).unwrap();

        let fd = open_read(installed).unwrap();
        let mut content = [0_u8; 9];
        assert_eq!(read(fd as usize, &mut content), Ok(9));
        assert_eq!(content, *b"installed");
        close(fd).unwrap();
        remove_file(installed).unwrap();
    }

    #[test]
    fn creates_and_removes_a_directory() {
        let path = c"/tmp/vibe-rt-directory-test";
        let _ = remove_directory(path);
        create_directory(path).unwrap();
        remove_directory(path).unwrap();
    }

    #[test]
    fn duplicates_a_descriptor() {
        let fd = open_read(c"/dev/null").unwrap();
        duplicate_to(fd, 99).unwrap();
        close(99).unwrap();
        close(fd).unwrap();
    }

    #[test]
    fn reads_the_current_directory() {
        let mut buffer = [0_u8; 4096];
        assert!(!current_dir(&mut buffer).unwrap().is_empty());
        change_dir(c".").unwrap();
    }

    #[test]
    fn reads_directory_entries() {
        let fd = open_directory(c".").unwrap();
        let mut buffer = [0_u8; 4096];
        assert_ne!(read_directory(fd, &mut buffer).unwrap(), 0);
        close(fd).unwrap();
    }

    #[test]
    fn configures_a_socket_read_timeout() {
        let fd = tcp_listener(0).unwrap();
        set_read_timeout(fd, 1).unwrap();
        close(fd).unwrap();
    }

    #[test]
    fn connects_outbound_ipv4_sockets() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = tcp_connect([127, 0, 0, 1], tcp.local_addr().unwrap().port()).unwrap();
        tcp.accept().unwrap();
        close(fd).unwrap();

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = udp_connect([127, 0, 0, 1], udp.local_addr().unwrap().port()).unwrap();
        write_all(fd as usize, b"vibe").unwrap();
        let mut bytes = [0_u8; 4];
        assert_eq!(udp.recv(&mut bytes).unwrap(), 4);
        assert_eq!(bytes, *b"vibe");
        close(fd).unwrap();
    }
}
