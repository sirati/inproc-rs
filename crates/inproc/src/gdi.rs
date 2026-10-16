//! Looking at GDI objects the process created.

use windows_sys::Win32::Graphics::Gdi::{GetObjectA, GetObjectType, LOGFONTA, OBJ_FONT};

/// The parameters a font was created with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFont {
    pub height: i32,
    pub width: i32,
    pub weight: i32,
    pub italic: bool,
    pub quality: u8,
    pub charset: u8,
    pub out_precision: u8,
    pub pitch_and_family: u8,
    pub face: String,
}

/// The LOGFONT of `handle`, if it is a font handle.
pub fn font(handle: u32) -> Option<LogFont> {
    let h = handle as usize as *mut core::ffi::c_void;
    // SAFETY: GetObjectType accepts any value and returns 0 for non-handles.
    if handle == 0 || unsafe { GetObjectType(h) } != OBJ_FONT as u32 {
        return None;
    }
    // SAFETY: plain struct, written by GetObjectA up to its size.
    let mut lf: LOGFONTA = unsafe { core::mem::zeroed() };
    let n = unsafe { GetObjectA(h, size_of::<LOGFONTA>() as i32, &mut lf as *mut LOGFONTA as *mut core::ffi::c_void) };
    if n <= 0 {
        return None;
    }
    let face: Vec<u8> = lf.lfFaceName.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    Some(LogFont {
        height: lf.lfHeight,
        width: lf.lfWidth,
        weight: lf.lfWeight,
        italic: lf.lfItalic != 0,
        quality: lf.lfQuality,
        charset: lf.lfCharSet,
        out_precision: lf.lfOutPrecision,
        pitch_and_family: lf.lfPitchAndFamily,
        face: String::from_utf8_lossy(&face).into_owned(),
    })
}
