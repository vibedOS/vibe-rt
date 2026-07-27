// SPDX-License-Identifier: MIT

#![no_std]

use core::arch::asm;
use core::ffi::{CStr, c_char, c_void};
use core::fmt::{self, Write};
use core::marker::PhantomData;
use core::ptr;
use core::slice;

const SYS_WRITE: usize = 1;
const SYS_READ: usize = 0;
const SYS_NANOSLEEP: usize = 35;
const SYS_GETPID: usize = 39;
const SYS_FORK: usize = 57;
const SYS_EXECVE: usize = 59;
const SYS_WAIT4: usize = 61;
const SYS_SYNC: usize = 162;
const SYS_PAUSE: usize = 34;
const SYS_MOUNT: usize = 165;
const SYS_REBOOT: usize = 169;
const SYS_EXIT_GROUP: usize = 231;

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

pub fn getpid() -> i32 {
    // SAFETY: getpid has no arguments and cannot fail.
    unsafe { syscall0(SYS_GETPID) as i32 }
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
#[cfg(not(test))]
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
    use super::{decode, memcpy, memmove, memset};

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
        }
    }
}
