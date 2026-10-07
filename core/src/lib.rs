//! Core of SailFactor: everything that touches secrets, behind a C API.
//! The core performs no I/O; the C++ bridge reads and writes files and
//! talks to the network.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod ffi;
