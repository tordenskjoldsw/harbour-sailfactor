//! Core of SailFactor: everything that touches secrets, behind a C API.
//! The core performs no I/O; the C++ bridge reads camera frames and files
//! and talks to the network.

#![deny(unsafe_op_in_unsafe_fn)]

mod argon2_memory;
pub mod ffi;
pub mod kdbx;
pub mod qr;
mod random;
mod secret;
