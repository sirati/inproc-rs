//! Copying plain-old-data out of foreign memory.

use std::fmt;
use std::marker::PhantomData;

use bytemuck::{Pod, Zeroable};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemError {
    #[error("null pointer")]
    Null,
    #[error("cannot read {len} bytes at {addr:#x}")]
    Unreadable { addr: u64, len: usize },
    #[error("address arithmetic overflow")]
    Overflow,
}

/// A pointer into a 32-bit foreign program's memory, typed as `T`.
///
/// It is a plain `u32`, so it can be embedded in `#[repr(C)]` mirrors of the
/// foreign program's structs and those keep the program's layout whatever
/// this crate is compiled for. It can only be read by copying
/// ([`read`](Ptr32::read)); any bit pattern must be a valid `T`
/// (`Pod`), since foreign memory can contain anything.
#[repr(transparent)]
pub struct Ptr32<T> {
    addr: u32,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for Ptr32<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Ptr32<T> {}
impl<T> PartialEq for Ptr32<T> {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}
impl<T> Eq for Ptr32<T> {}
impl<T> std::hash::Hash for Ptr32<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state)
    }
}
impl<T> fmt::Debug for Ptr32<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.addr)
    }
}

// SAFETY: `repr(transparent)` over a `u32`; the PhantomData is zero-sized and
// carries no data, so every bit pattern is valid and there is no padding.
unsafe impl<T: 'static> Zeroable for Ptr32<T> {}
unsafe impl<T: 'static> Pod for Ptr32<T> {}

impl<T> Ptr32<T> {
    pub const NULL: Self = Self::new(0);

    pub const fn new(addr: u32) -> Self {
        Self { addr, _t: PhantomData }
    }

    pub const fn raw(self) -> u32 {
        self.addr
    }

    pub const fn is_null(self) -> bool {
        self.addr == 0
    }

    /// The same address seen as another type.
    pub const fn cast<U>(self) -> Ptr32<U> {
        Ptr32::new(self.addr)
    }

    /// `byte_offset` bytes further, as type `U` (e.g. a field).
    pub fn offset<U>(self, byte_offset: u32) -> Result<Ptr32<U>, MemError> {
        self.addr.checked_add(byte_offset).map(Ptr32::new).ok_or(MemError::Overflow)
    }

    /// Element `i` of an array of `T` starting here (`T`'s size is taken to
    /// be the foreign one, i.e. `T` must be a faithful mirror).
    pub fn index(self, i: u32) -> Result<Ptr32<T>, MemError> {
        (size_of::<T>() as u32)
            .checked_mul(i)
            .and_then(|o| self.addr.checked_add(o))
            .map(Ptr32::new)
            .ok_or(MemError::Overflow)
    }
}

impl<T: Pod> Ptr32<T> {
    /// Copies the value out.
    pub fn read(self) -> Result<T, MemError> {
        let mut value = T::zeroed();
        read_bytes(self.addr as u64, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    /// Copies `n` consecutive values out.
    pub fn read_array(self, n: usize) -> Result<Vec<T>, MemError> {
        let mut values = vec![T::zeroed(); n];
        read_bytes(self.addr as u64, bytemuck::cast_slice_mut(&mut values))?;
        Ok(values)
    }
}

/// Copies `out.len()` bytes from address `addr` of this process.
pub fn read_bytes(addr: u64, out: &mut [u8]) -> Result<(), MemError> {
    if out.is_empty() {
        return Ok(());
    }
    if addr == 0 {
        return Err(MemError::Null);
    }
    addr.checked_add(out.len() as u64).ok_or(MemError::Overflow)?;
    imp::read(addr, out)
}

#[cfg(windows)]
mod imp {
    use super::MemError;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    pub fn read(addr: u64, out: &mut [u8]) -> Result<(), MemError> {
        let src = usize::try_from(addr).map_err(|_| MemError::Unreadable { addr, len: out.len() })?;
        let mut done = 0usize;
        // SAFETY: `out` is a valid, exclusively borrowed buffer of
        // `out.len()` bytes. The source is never dereferenced by us: the
        // kernel validates and copies it, failing on unmapped or protected
        // pages instead of faulting.
        let ok = unsafe {
            ReadProcessMemory(GetCurrentProcess(), src as *const _, out.as_mut_ptr().cast(), out.len(), &mut done)
        };
        if ok == 0 || done != out.len() {
            return Err(MemError::Unreadable { addr, len: out.len() });
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::MemError;

    /// Off Windows the crate only exists so that dependents type-check and
    /// test their pure logic; there is no foreign memory to read.
    pub fn read(addr: u64, out: &mut [u8]) -> Result<(), MemError> {
        Err(MemError::Unreadable { addr, len: out.len() })
    }
}

#[cfg(all(test, windows, target_pointer_width = "32"))]
mod tests {
    use super::*;

    #[test]
    fn reads_own_memory_and_rejects_garbage() {
        let data: [u32; 3] = [7, 8, 9];
        let p = Ptr32::<u32>::new(data.as_ptr() as u32);
        assert_eq!(p.read().unwrap(), 7);
        assert_eq!(p.index(2).unwrap().read().unwrap(), 9);
        assert_eq!(p.read_array(3).unwrap(), vec![7, 8, 9]);
        assert_eq!(Ptr32::<u32>::NULL.read(), Err(MemError::Null));
        assert!(matches!(Ptr32::<u32>::new(16).read(), Err(MemError::Unreadable { .. })));
    }
}
