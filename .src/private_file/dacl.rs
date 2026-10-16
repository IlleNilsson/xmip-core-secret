//! The owner-only access a private file and its directory carry on Windows:
//! a discretionary access control list granting full control to the user
//! this process runs as and to `SYSTEM`, and to no one else, protected from
//! what the folder above would pass down.
//!
//! The one file in this crate that may hold unsafe code (ADR-0050, amendment
//! 2026-09-25): the access lists of files are a C interface, reached no other
//! way. Every block says where its pointers come from, how long they live
//! and who frees what they hand back.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Error, Result};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, GENERIC_WRITE, HANDLE, LocalFree, WIN32_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The access list, in Security Descriptor Definition Language, a private
/// file carries — or, `directory`, a private directory, whose entries what
/// is made inside it inherits.
///
/// # Errors
///
/// Where Windows does not say which user this process runs as.
pub fn owner_only(directory: bool) -> Result<String> {
    let user = user()?;
    let inherit = if directory { "OICI" } else { "" };
    // P: protected, nothing inherited from above; AI: what Windows marks on
    // every list it sets, said here so the list read back is this one.
    Ok(format!(
        "D:PAI(A;{inherit};FA;;;{user})(A;{inherit};FA;;;SY)"
    ))
}

/// The access list `path` carries, in Security Descriptor Definition
/// Language: what a test compares with [`owner_only`].
///
/// # Errors
///
/// Where `path` cannot be opened or Windows does not say.
pub fn described(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the handle is `file`'s, open for this call with READ_CONTROL.
    // The owner, group and list pointers are null, which asks for none of
    // them back; `descriptor` is a local Windows fills with a LocalAlloc'd
    // descriptor, freed by `Local` when it drops.
    let status = unsafe {
        GetSecurityInfo(
            raw(&file),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    succeeded(status)?;
    let descriptor = Local(descriptor);
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `descriptor` is the live descriptor Windows just handed back.
    // `text` is a local Windows fills with a LocalAlloc'd, null-terminated
    // string, read by `wide` and freed by `Local`; the length is not asked.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &raw mut text,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(Error::last_os_error());
    }
    let text = Local(text.cast());
    Ok(wide(text.0.cast()))
}

/// A new file at `path`, created owner-only before a byte is written: held
/// open for no one else (share mode none) while [`owner_only`]'s list is set
/// on it, so no other handle can be opened before the list is there.
///
/// # Errors
///
/// Where the file is there already, cannot be created, or the list cannot be
/// set; the file is removed again in the last case.
pub fn create(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_WRITE | WRITE_DAC | READ_CONTROL)
        .share_mode(0)
        .open(path)?;
    if let Err(failure) = protect(&file, false) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(failure);
    }
    Ok(file)
}

/// Set [`owner_only`]'s list on the directory at `path`, just made and still
/// empty, so what is made inside it inherits that list.
///
/// # Errors
///
/// Where the directory cannot be opened or the list cannot be set.
pub fn protect_directory(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .access_mode(WRITE_DAC | READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    protect(&directory, true)
}

/// Set [`owner_only`]'s list on `file`, opened with `WRITE_DAC`.
fn protect(file: &File, directory: bool) -> Result<()> {
    let sddl: Vec<u16> = owner_only(directory)?
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `sddl` is a null-terminated UTF-16 string alive for the call.
    // `descriptor` is a local Windows fills with a LocalAlloc'd descriptor,
    // freed by `Local` when it drops; its size is not asked.
    let made = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    };
    if made == 0 {
        return Err(Error::last_os_error());
    }
    let descriptor = Local(descriptor);
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `descriptor` is live until `Local` drops at the end of this
    // function; `dacl` points into it and is used only before then.
    let found = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if found == 0 || present == 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: the handle is `file`'s, opened with WRITE_DAC and open for the
    // call; `dacl` points into `descriptor`, live until this function ends.
    // Owner, group and system list are null: they are not changed.
    let status = unsafe {
        SetSecurityInfo(
            raw(file),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    succeeded(status)
}

/// The user this process runs as, its security identifier as text.
fn user() -> Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess answers a pseudo handle that needs no
    // closing; `token` is a local Windows fills with a handle we own.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `token` was just opened for us and is closed once, when
    // `owned` drops.
    let owned = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0u32;
    // SAFETY: a null buffer of size 0 asks only for the size, into `size`.
    unsafe { GetTokenInformation(raw(&owned), TokenUser, ptr::null_mut(), 0, &raw mut size) };
    // u64 words, so the buffer is aligned for TOKEN_USER and its pointers.
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: `buffer` has room for `size` bytes, as the call said it needs.
    let read = unsafe {
        GetTokenInformation(
            raw(&owned),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    };
    if read == 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: Windows wrote a TOKEN_USER at the start of `buffer`, aligned
    // as u64; its SID points further into `buffer`, alive below.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` points into `buffer`, alive for the call; `text` is a
    // local Windows fills with a LocalAlloc'd string, freed by `Local`.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(Error::last_os_error());
    }
    let text = Local(text.cast());
    Ok(wide(text.0.cast()))
}

/// A handle as the Windows calls take it.
fn raw(handle: &impl AsRawHandle) -> HANDLE {
    handle.as_raw_handle()
}

/// A Windows status as a result.
fn succeeded(status: WIN32_ERROR) -> Result<()> {
    if status == ERROR_SUCCESS {
        return Ok(());
    }
    Err(Error::from_raw_os_error(status.cast_signed()))
}

/// The null-terminated UTF-16 string at `text`.
fn wide(text: *const u16) -> String {
    let mut length = 0;
    // SAFETY: `text` is a null-terminated string Windows allocated, alive
    // until its `Local` drops after this returns; it is read up to its null.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    }
}

/// Memory Windows allocated with `LocalAlloc`, freed once when dropped.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Windows call that allocates with
        // LocalAlloc, is owned by this value alone and is freed once, here;
        // a null pointer is freed as nothing.
        unsafe { LocalFree(self.0) };
    }
}
