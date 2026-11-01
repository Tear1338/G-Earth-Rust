//! Ownership of a launched runtime and its descendant processes.
use std::{io,process::{Child,Command}};
pub struct ProcessTree {#[cfg(windows)] job:isize,#[cfg(unix)] group:i32}
impl ProcessTree {
    pub fn prepare(command:&mut Command) {
        #[cfg(windows)] {use std::os::windows::process::CommandExt;command.creation_flags(0x08000000);}
        #[cfg(unix)] {use std::os::unix::process::CommandExt;command.process_group(0);}
        let _=command;
    }
    pub fn attach(child:&Child)->io::Result<Self> {
        #[cfg(windows)] {use std::os::windows::io::AsRawHandle;use windows_sys::Win32::{Foundation::CloseHandle,System::JobObjects::{CreateJobObjectW,SetInformationJobObject,AssignProcessToJobObject,JobObjectExtendedLimitInformation,JOBOBJECT_EXTENDED_LIMIT_INFORMATION,JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE}};
            let job=unsafe{CreateJobObjectW(std::ptr::null(),std::ptr::null())};if job.is_null(){return Err(io::Error::last_os_error());}let mut limits:JOBOBJECT_EXTENDED_LIMIT_INFORMATION=unsafe{std::mem::zeroed()};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured=unsafe{SetInformationJobObject(job,JobObjectExtendedLimitInformation,(&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),std::mem::size_of_val(&limits) as u32)};let assigned=if configured!=0{unsafe{AssignProcessToJobObject(job,child.as_raw_handle().cast())}}else{0};if assigned==0{let error=io::Error::last_os_error();unsafe{CloseHandle(job);}return Err(error);}Ok(Self {job:job as isize})
        }
        #[cfg(unix)] {let group=i32::try_from(child.id()).map_err(io::Error::other)?;if group<=0{return Err(io::Error::other("invalid runtime process group"));}Ok(Self {group})}
        #[cfg(not(any(unix,windows)))] {let _=child;Err(io::Error::new(io::ErrorKind::Unsupported,"runtime process ownership is unsupported"))}
    }
}
impl Drop for ProcessTree {fn drop(&mut self){
    #[cfg(windows)] unsafe {windows_sys::Win32::Foundation::CloseHandle(self.job as *mut std::ffi::c_void);}
    #[cfg(unix)] unsafe {unsafe extern "C" {fn kill(pid:i32,signal:i32)->i32;}kill(-self.group,9);}
}}
