//! Looking at GDI objects the process created.

use windows_sys::Win32::Graphics::Gdi::{GetCurrentObject, GetObjectA, GetObjectType, GetTextColor, LOGFONTA, OBJ_FONT};

/// The parameters a font was created with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFont {
    pub height: i32,
    pub width: i32,
    pub weight: i32,
    pub italic: bool,
    pub underline: bool,
    pub quality: u8,
    pub charset: u8,
    pub out_precision: u8,
    pub pitch_and_family: u8,
    pub face: String,
}

/// The font selected into device context `dc`.
pub fn dc_font(dc: u32) -> Option<LogFont> {
    // SAFETY: GetCurrentObject accepts any value, NULL for non-DCs.
    let h = unsafe { GetCurrentObject(dc as usize as *mut core::ffi::c_void, OBJ_FONT as u32) };
    font(h as usize as u32)
}

/// The text colour of `dc` as (r, g, b).
pub fn dc_text_color(dc: u32) -> (u8, u8, u8) {
    // SAFETY: returns CLR_INVALID for non-DCs.
    let c = unsafe { GetTextColor(dc as usize as *mut core::ffi::c_void) };
    // `DIBINDEX(i)` (0x10FF00ii): a colour-table index; the canvases are
    // 16-bit DIBs without a table, where GDI draws pixel value 0, black.
    if c >> 16 == 0x10FF {
        return (0, 0, 0);
    }
    (c as u8, (c >> 8) as u8, (c >> 16) as u8)
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
        underline: lf.lfUnderline != 0,
        quality: lf.lfQuality,
        charset: lf.lfCharSet,
        out_precision: lf.lfOutPrecision,
        pitch_and_family: lf.lfPitchAndFamily,
        face: String::from_utf8_lossy(&face).into_owned(),
    })
}

/// The text colour of `dc` exactly as `GetTextColor` returns it (a
/// `COLORREF`, or `DIBINDEX(i)` = 0x10FF00ii; `CLR_INVALID` for non-DCs).
pub fn dc_text_colorref(dc: u32) -> u32 {
    // SAFETY: returns CLR_INVALID for non-DCs.
    unsafe { GetTextColor(dc as usize as *mut core::ffi::c_void) }
}

/// The LOGFONT of stock object `index` (`GetStockObject`, e.g. 13 for
/// `SYSTEM_FONT`), if it is a font.
pub fn stock_font(index: i32) -> Option<LogFont> {
    // SAFETY: GetStockObject accepts any index and returns NULL for unknown ones.
    let h = unsafe { windows_sys::Win32::Graphics::Gdi::GetStockObject(index as _) };
    font(h as usize as u32)
}
