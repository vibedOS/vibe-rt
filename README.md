# vibe-rt

`vibe-rt` is the minimal `no_std`, libc-free x86_64 Linux userspace runtime
shared by vibeOS programs. It provides process entry and direct Linux syscall
wrappers without a C runtime.

## Provided interfaces

- `_start` integration through the `entry!` macro
- byte-preserving argument and environment iterators
- console and file-descriptor reads and writes
- TCP listen, accept, and read timeouts
- file open, directory reads, create, remove, atomic rename, `fsync`, mode
  changes, `dup2`, `chdir`, and `getcwd`
- filesystem mounting
- `fork`, `execve`, child waits, process IDs, user IDs, sleep, and exit
- parent-death signaling
- filesystem sync and reboot
- `print!`, `println!`, and `eprintln!`
- compiler memory and byte-comparison symbols required by libc-free binaries

The API returns raw Linux error numbers through `Errno`; it does not try to be
a general Unix compatibility layer.

## Build and test

Rust 1.94.0 is selected by `rust-toolchain.toml`.

```sh
cargo build --release
cargo test
```

The tests exercise startup-stack parsing, environment lookup, error decoding,
and filesystem wrappers on the Linux host.

Programs use `entry!` instead of the standard Rust runtime:

```rust
#![no_main]
#![no_std]

use vibe_rt::{Args, Env, entry};

entry!(main);

fn main(_args: Args<'_>, _env: Env<'_>) -> i32 {
    vibe_rt::println!("hello from vibeOS");
    0
}
```

## Scope

The runtime currently targets x86_64 Linux only. It intentionally has no
allocator, threads, dynamic linking, libc compatibility, or stable API
guarantee.

## License

MIT
