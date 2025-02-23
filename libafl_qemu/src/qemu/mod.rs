//! Low-level QEMU library
//!
//! This module exposes the low-level QEMU library through [`Qemu`].
//! To access higher-level features of QEMU, it is recommanded to use [`crate::Emulator`] instead.

use core::fmt;
use std::{
    cmp::{Ordering, PartialOrd},
    ffi::CString,
    fmt::{Display, Formatter},
    intrinsics::{copy_nonoverlapping, transmute},
    mem::MaybeUninit,
    ops::Range,
    pin::Pin,
    ptr,
};

use libafl_bolts::os::unix_signals::Signal;
#[cfg(emulation_mode = "systemmode")]
use libafl_qemu_sys::qemu_init;
#[cfg(emulation_mode = "usermode")]
use libafl_qemu_sys::{guest_base, qemu_user_init, VerifyAccess};
use libafl_qemu_sys::{
    libafl_flush_jit, libafl_get_exit_reason, libafl_page_from_addr, libafl_qemu_add_gdb_cmd,
    libafl_qemu_cpu_index, libafl_qemu_current_cpu, libafl_qemu_gdb_reply, libafl_qemu_get_cpu,
    libafl_qemu_num_cpus, libafl_qemu_num_regs, libafl_qemu_read_reg,libafl_get_first_cpu,libafl_paddr2host,
    libafl_qemu_remove_breakpoint, libafl_qemu_set_breakpoint,libafl_qemu_flush_tb,libafl_qemu_get_infuzz,libafl_qemu_set_infuzz,
    libafl_qemu_exit_timeout,libafl_qemu_exit_stream_notfound,libafl_qemu_exit_stream_outof,libafl_qemu_exit_crash,libafl_qemu_in_smm_mode,libafl_qemu_cpu_stopped,
    libafl_qemu_write_reg, CPUArchState, CPUStatePtr, FatPtr, GuestAddr, GuestPhysAddr, GuestUsize,
    GuestVirtAddr,
};
use num_traits::Num;
use strum::IntoEnumIterator;

use crate::{GuestAddrKind, GuestReg, Regs};

#[cfg(emulation_mode = "usermode")]
mod usermode;
#[cfg(emulation_mode = "usermode")]
pub use usermode::*;

#[cfg(emulation_mode = "systemmode")]
mod systemmode;
#[cfg(emulation_mode = "systemmode")]
#[allow(unused_imports)]
pub use systemmode::*;

mod hooks;
pub use hooks::*;

static mut QEMU_IS_INITIALIZED: bool = false;

#[derive(Debug)]
pub enum QemuInitError {
    MultipleInstances,
    EmptyArgs,
    TooManyArgs(usize),
}

#[derive(Debug, Clone)]
pub enum QemuExitReason {
    End(QemuShutdownCause), // QEMU ended for some reason.
    Breakpoint(GuestAddr),  // Breakpoint triggered. Contains the address of the trigger.
    SyncExit, // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
    Timeout,
    StreamNotFound,
    StreamOutof,
    Crash,
}

#[derive(Debug, Clone)]
pub enum QemuExitError {
    UnknownKind, // Exit reason was not NULL, but exit kind is unknown. Should never happen.
    UnexpectedExit, // Qemu exited without going through an expected exit point. Can be caused by a crash for example.
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuSnapshotCheckResult {
    nb_page_inconsistencies: u64,
}

#[derive(Debug, Clone)]
pub enum QemuRWErrorKind {
    Read,
    Write,
}

#[derive(Debug, Clone)]
pub enum QemuRWErrorCause {
    WrongCallingConvention(CallingConvention, CallingConvention), // expected, given
    WrongArgument(i32),
    CurrentCpuNotFound,
    Reg(i32),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct QemuRWError {
    kind: QemuRWErrorKind,
    cause: QemuRWErrorCause,
    cpu: Option<CPUStatePtr>, // Only makes sense when cause != CurrentCpuNotFound
}

impl QemuRWError {
    #[must_use]
    pub fn new(kind: QemuRWErrorKind, cause: QemuRWErrorCause, cpu: Option<CPUStatePtr>) -> Self {
        Self { kind, cause, cpu }
    }

    #[must_use]
    pub fn current_cpu_not_found(kind: QemuRWErrorKind) -> Self {
        Self::new(kind, QemuRWErrorCause::CurrentCpuNotFound, None)
    }

    #[must_use]
    pub fn new_argument_error(kind: QemuRWErrorKind, reg_id: i32) -> Self {
        Self::new(kind, QemuRWErrorCause::WrongArgument(reg_id), None)
    }

    pub fn check_conv(
        kind: QemuRWErrorKind,
        expected_conv: CallingConvention,
        given_conv: CallingConvention,
    ) -> Result<(), Self> {
        if expected_conv != given_conv {
            return Err(Self::new(
                kind,
                QemuRWErrorCause::WrongCallingConvention(expected_conv, given_conv),
                None,
            ));
        }

        Ok(())
    }
}

/// Represents a QEMU snapshot check result for which no error was detected
impl Default for QemuSnapshotCheckResult {
    fn default() -> Self {
        Self {
            nb_page_inconsistencies: 0,
        }
    }
}

/// The thin wrapper around QEMU.
/// It is considered unsafe to use it directly.
/// Prefer using `Emulator` instead in case of doubt.
#[derive(Clone, Copy, Debug)]
pub struct Qemu {
    _private: (),
}

#[derive(Debug, Clone)]
pub struct QemuMemoryChunk {
    addr: GuestAddrKind,
    size: GuestReg,
    cpu: Option<CPU>,
}

#[allow(clippy::vec_box)]
static mut GDB_COMMANDS: Vec<Box<FatPtr>> = vec![];

extern "C" fn gdb_cmd(data: *const (), buf: *const u8, len: usize) -> i32 {
    unsafe {
        let closure = &mut *(data as *mut Box<dyn for<'r> FnMut(&Qemu, &'r str) -> bool>);
        let cmd = std::str::from_utf8_unchecked(std::slice::from_raw_parts(buf, len));
        let qemu = Qemu::get_unchecked();
        i32::from(closure(&qemu, cmd))
    }
}

#[derive(Debug, Clone)]
pub enum QemuShutdownCause {
    None,
    HostError,
    HostQmpQuit,
    HostQmpSystemReset,
    HostSignal(Signal),
    HostUi,
    GuestShutdown,
    GuestReset,
    GuestPanic,
    SubsystemReset,
    SnapshotLoad,
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct MemAccessInfo {
    oi: libafl_qemu_sys::MemOpIdx,
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct CPU {
    ptr: CPUStatePtr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallingConvention {
    Cdecl,
}

pub trait HookId {
    fn remove(&self, invalidate_block: bool) -> bool;
}

#[derive(Debug)]
pub struct HookData(u64);

impl std::error::Error for QemuInitError {}

impl Display for QemuInitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QemuInitError::MultipleInstances => {
                write!(f, "Only one instance of the QEMU Emulator is permitted")
            }
            QemuInitError::EmptyArgs => {
                write!(f, "QEMU emulator args cannot be empty")
            }
            QemuInitError::TooManyArgs(n) => {
                write!(
                    f,
                    "Too many arguments passed to QEMU emulator ({n} > i32::MAX)"
                )
            }
        }
    }
}

impl From<QemuInitError> for libafl::Error {
    fn from(err: QemuInitError) -> Self {
        libafl::Error::unknown(format!("{err}"))
    }
}

impl Display for QemuExitReason {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            QemuExitReason::End(shutdown_cause) => write!(f, "End: {shutdown_cause:?}"),
            QemuExitReason::Breakpoint(bp) => write!(f, "Breakpoint: {bp}"),
            QemuExitReason::SyncExit => write!(f, "Sync Exit"),
            QemuExitReason::Timeout => write!(f, "Timeout"),
            QemuExitReason::StreamNotFound => write!(f, "StreamNotFound"),
            QemuExitReason::StreamOutof => write!(f, "StreamOutof"),
            QemuExitReason::Crash => write!(f, "Crash"),
        }
    }
}

impl MemAccessInfo {
    #[must_use]
    pub fn memop(&self) -> libafl_qemu_sys::MemOp {
        libafl_qemu_sys::MemOp(self.oi >> 4)
    }

    #[must_use]
    pub fn memopidx(&self) -> libafl_qemu_sys::MemOpIdx {
        self.oi
    }

    #[must_use]
    pub fn mmu_index(&self) -> u32 {
        self.oi & 15
    }

    #[must_use]
    pub fn size(&self) -> usize {
        libafl_qemu_sys::memop_size(self.memop()) as usize
    }

    #[must_use]
    pub fn is_big_endian(&self) -> bool {
        libafl_qemu_sys::memop_big_endian(self.memop())
    }

    #[must_use]
    pub fn encode_with(&self, other: u32) -> u64 {
        (u64::from(self.oi) << 32) | u64::from(other)
    }

    #[must_use]
    pub fn decode_from(encoded: u64) -> (Self, u32) {
        let low = (encoded & 0xFFFFFFFF) as u32;
        let high = (encoded >> 32) as u32;
        (Self { oi: high }, low)
    }

    #[must_use]
    pub fn new(oi: libafl_qemu_sys::MemOpIdx) -> Self {
        Self { oi }
    }
}

impl From<libafl_qemu_sys::MemOpIdx> for MemAccessInfo {
    fn from(oi: libafl_qemu_sys::MemOpIdx) -> Self {
        Self { oi }
    }
}

pub trait ArchExtras {
    fn read_return_address<T>(&self) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>;
    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>;
    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>;
    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>;
}

#[allow(clippy::unused_self)]
impl CPU {
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn index(&self) -> usize {
        unsafe { libafl_qemu_cpu_index(self.ptr) as usize }
    }

    pub fn exit_timeout(&self) {
        unsafe {
            libafl_qemu_exit_timeout(self.ptr);
        }
    }
    pub fn exit_stream_notfound(&self) {
        unsafe {
            libafl_qemu_exit_stream_notfound(self.ptr);
        }
    }
    pub fn exit_stream_outof(&self) {
        unsafe {
            libafl_qemu_exit_stream_outof(self.ptr);
        }
    }
    pub fn exit_crash(&self) {
        unsafe {
            libafl_qemu_exit_crash(self.ptr);
        }
    }
    pub fn smm_mode(&self) -> bool {
        unsafe {
            libafl_qemu_in_smm_mode()
        }
    }
    pub fn get_host_addr(&self, addr : u64) -> *mut u8 {
        unsafe {
            libafl_paddr2host(self.ptr, addr, true)
        }
    }
    pub fn stopped(&self) -> bool {
        unsafe { 
            libafl_qemu_cpu_stopped(self.ptr) 
        }
    }
    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        unsafe { (addr as usize + guest_base) as *mut T }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        unsafe { (addr as usize - guest_base) as GuestAddr }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        unsafe {
            // TODO add support for tagged GuestAddr
            libafl_qemu_sys::page_check_range(addr, size as GuestAddr, kind.into())
        }
    }

    // TODO expose tlb_set_dirty and tlb_reset_dirty

    #[must_use]
    pub fn num_regs(&self) -> i32 {
        unsafe { libafl_qemu_num_regs(self.ptr) }
    }

    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), QemuRWError>
    where
        R: Into<i32> + Clone,
        T: Into<GuestReg>,
    {
        let reg_id = reg.clone().into();
        #[cfg(feature = "be")]
        let val = GuestReg::to_be(val.into());

        #[cfg(not(feature = "be"))]
        let val = GuestReg::to_le(val.into());

        let success =
            unsafe { libafl_qemu_write_reg(self.ptr, reg_id, ptr::addr_of!(val) as *const u8) };
        if success == 0 {
            Err(QemuRWError {
                kind: QemuRWErrorKind::Write,
                cause: QemuRWErrorCause::Reg(reg.into()),
                cpu: Some(self.ptr),
            })
        } else {
            Ok(())
        }
    }

    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, QemuRWError>
    where
        R: Into<i32> + Clone,
        T: From<GuestReg>,
    {
        unsafe {
            let reg_id = reg.clone().into();
            let mut val = MaybeUninit::uninit();
            let success = libafl_qemu_read_reg(self.ptr, reg_id, val.as_mut_ptr() as *mut u8);
            if success == 0 {
                Err(QemuRWError {
                    kind: QemuRWErrorKind::Write,
                    cause: QemuRWErrorCause::Reg(reg.into()),
                    cpu: Some(self.ptr),
                })
            } else {
                #[cfg(feature = "be")]
                return Ok(GuestReg::from_be(val.assume_init()).into());

                #[cfg(not(feature = "be"))]
                return Ok(GuestReg::from_le(val.assume_init()).into());
            }
        }
    }

    pub fn reset(&self) {
        unsafe { libafl_qemu_sys::cpu_reset(self.ptr) };
    }

    #[must_use]
    pub fn save_state(&self) -> CPUArchState {
        unsafe {
            let mut saved = MaybeUninit::<CPUArchState>::uninit();
            copy_nonoverlapping(
                libafl_qemu_sys::cpu_env(self.ptr.as_mut().unwrap()),
                saved.as_mut_ptr(),
                1,
            );
            saved.assume_init()
        }
    }

    pub fn restore_state(&self, saved: &CPUArchState) {
        unsafe {
            copy_nonoverlapping(
                saved,
                libafl_qemu_sys::cpu_env(self.ptr.as_mut().unwrap()),
                1,
            );
        }
    }

    #[must_use]
    pub fn raw_ptr(&self) -> CPUStatePtr {
        self.ptr
    }

    #[must_use]
    pub fn display_context(&self) -> String {
        let mut display = String::new();
        let mut maxl = 0;
        for r in Regs::iter() {
            maxl = std::cmp::max(format!("{r:#?}").len(), maxl);
        }
        for (i, r) in Regs::iter().enumerate() {
            let v: GuestAddr = self.read_reg(r).unwrap();
            let sr = format!("{r:#?}");
            display += &format!("{sr:>maxl$}: {v:#016x} ");
            if (i + 1) % 4 == 0 {
                display += "\n";
            }
        }
        if !display.ends_with('\n') {
            display += "\n";
        }
        display
    }
}

impl<T> From<Pin<&mut T>> for HookData {
    fn from(value: Pin<&mut T>) -> Self {
        unsafe { HookData(transmute::<Pin<&mut T>, u64>(value)) }
    }
}

impl<T> From<Pin<&T>> for HookData {
    fn from(value: Pin<&T>) -> Self {
        unsafe { HookData(transmute::<Pin<&T>, u64>(value)) }
    }
}

impl<T> From<&'static mut T> for HookData {
    fn from(value: &'static mut T) -> Self {
        unsafe { HookData(transmute::<&mut T, u64>(value)) }
    }
}

impl<T> From<&'static T> for HookData {
    fn from(value: &'static T) -> Self {
        unsafe { HookData(transmute::<&T, u64>(value)) }
    }
}

impl<T> From<*mut T> for HookData {
    fn from(value: *mut T) -> Self {
        HookData(value as u64)
    }
}

impl<T> From<*const T> for HookData {
    fn from(value: *const T) -> Self {
        HookData(value as u64)
    }
}

impl From<u64> for HookData {
    fn from(value: u64) -> Self {
        HookData(value)
    }
}

impl From<u32> for HookData {
    fn from(value: u32) -> Self {
        HookData(u64::from(value))
    }
}

impl From<u16> for HookData {
    fn from(value: u16) -> Self {
        HookData(u64::from(value))
    }
}

impl From<u8> for HookData {
    fn from(value: u8) -> Self {
        HookData(u64::from(value))
    }
}

#[allow(clippy::unused_self)]
impl Qemu {
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn init(args: &[String], env: &[(String, String)]) -> Result<Self, QemuInitError> {
        if args.is_empty() {
            return Err(QemuInitError::EmptyArgs);
        }

        let argc = args.len();
        if i32::try_from(argc).is_err() {
            return Err(QemuInitError::TooManyArgs(argc));
        }

        unsafe {
            if QEMU_IS_INITIALIZED {
                return Err(QemuInitError::MultipleInstances);
            }
            QEMU_IS_INITIALIZED = true;
        }

        #[allow(clippy::cast_possible_wrap)]
        let argc = argc as i32;

        let args: Vec<CString> = args
            .iter()
            .map(|x| CString::new(x.clone()).unwrap())
            .collect();
        let mut argv: Vec<*const u8> = args.iter().map(|x| x.as_ptr() as *const u8).collect();
        argv.push(ptr::null()); // argv is always null terminated.
        let env_strs: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("{}={}\0", &k, &v))
            .collect();
        let mut envp: Vec<*const u8> = env_strs.iter().map(|x| x.as_bytes().as_ptr()).collect();
        envp.push(ptr::null());
        unsafe {
            #[cfg(emulation_mode = "usermode")]
            qemu_user_init(argc, argv.as_ptr(), envp.as_ptr());
            #[cfg(emulation_mode = "systemmode")]
            {
                qemu_init(argc, argv.as_ptr(), envp.as_ptr());
                libc::atexit(qemu_cleanup_atexit);
                libafl_qemu_sys::syx_snapshot_init(false);
            }
        }

        Ok(Qemu { _private: ()})
    }
    pub fn get_infuzz(&self) -> bool {
        unsafe {
            libafl_qemu_get_infuzz()
        }
    }
    pub fn set_infuzz(&mut self, infuzz : bool) {
        unsafe {
            libafl_qemu_set_infuzz(infuzz);
        }
    }
    pub fn flush_tb(&self) {
        unsafe { libafl_qemu_flush_tb(); }
    }
    #[must_use]
    pub fn hooks(&self) -> QemuHooks {
        unsafe { QemuHooks::get_unchecked() }
    }

    /// Get a QEMU object.
    /// Same as `Qemu::get`, but without checking whether QEMU has been correctly initialized.
    /// Since Qemu is a ZST, this operation is free.
    ///
    /// # Safety
    ///
    /// Should not be used if `Qemu::init` has never been used before (otherwise QEMU will not be initialized, and a crash will occur).
    /// Prefer `Qemu::get` for a safe version of this method.
    #[must_use]
    pub unsafe fn get_unchecked() -> Self {
        Qemu { _private: ()}
    }

    #[must_use]
    pub fn get() -> Option<Self> {
        unsafe {
            if QEMU_IS_INITIALIZED {
                Some(Qemu { _private: ()})
            } else {
                None
            }
        }
    }

    /// This function will run the emulator until the next breakpoint / sync exit, or until finish.
    /// It is a low-level function and simply kicks QEMU.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(&self) -> Result<QemuExitReason, QemuExitError> {
        self.run_inner();

        let exit_reason = unsafe { libafl_get_exit_reason() };
        if exit_reason.is_null() {
            Err(QemuExitError::UnexpectedExit)
        } else {
            let exit_reason: &mut libafl_qemu_sys::libafl_exit_reason =
                unsafe { transmute(&mut *exit_reason) };
            Ok(match exit_reason.kind {
                libafl_qemu_sys::libafl_exit_reason_kind_INTERNAL => unsafe {
                    let qemu_shutdown_cause: QemuShutdownCause =
                        match exit_reason.data.internal.cause {
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_NONE => {
                                QemuShutdownCause::None
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_ERROR => {
                                QemuShutdownCause::HostError
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_QMP_QUIT => {
                                QemuShutdownCause::HostQmpQuit
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_QMP_SYSTEM_RESET => {
                                QemuShutdownCause::HostQmpSystemReset
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_SIGNAL => {
                                QemuShutdownCause::HostSignal(
                                    Signal::try_from(exit_reason.data.internal.signal).unwrap(),
                                )
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_UI => {
                                QemuShutdownCause::HostUi
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_GUEST_SHUTDOWN => {
                                QemuShutdownCause::GuestShutdown
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_GUEST_RESET => {
                                QemuShutdownCause::GuestReset
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_GUEST_PANIC => {
                                QemuShutdownCause::GuestPanic
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_SUBSYSTEM_RESET => {
                                QemuShutdownCause::SubsystemReset
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_SNAPSHOT_LOAD => {
                                QemuShutdownCause::SnapshotLoad
                            }

                            _ => panic!("shutdown cause not handled."),
                        };

                    QemuExitReason::End(qemu_shutdown_cause)
                },
                libafl_qemu_sys::libafl_exit_reason_kind_BREAKPOINT => unsafe {
                    let bp_addr = exit_reason.data.breakpoint.addr;
                    QemuExitReason::Breakpoint(bp_addr)
                },
                libafl_qemu_sys::libafl_exit_reason_kind_SYNC_EXIT => QemuExitReason::SyncExit,
                libafl_qemu_sys::libafl_exit_reason_kind_TIMEOUT => QemuExitReason::Timeout,
                libafl_qemu_sys::libafl_exit_reason_kind_STREAM_NOTFOUND => QemuExitReason::StreamNotFound,
                libafl_qemu_sys::libafl_exit_reason_kind_STREAM_OUTOF => QemuExitReason::StreamOutof,
                libafl_qemu_sys::libafl_exit_reason_kind_CRASH => QemuExitReason::Crash,
                _ => return Err(QemuExitError::UnknownKind),
            })
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    pub fn num_cpus(&self) -> usize {
        unsafe { libafl_qemu_num_cpus() as usize }
    }

    #[must_use]
    pub fn current_cpu(&self) -> Option<CPU> {
        let ptr = unsafe { libafl_qemu_current_cpu() };
        if ptr.is_null() {
            None
        } else {
            Some(CPU { ptr })
        }
    }

    #[must_use]
    pub fn first_cpu(&self) -> Option<CPU> {
        let ptr = unsafe { libafl_get_first_cpu() };
        if ptr.is_null() {
            None
        } else {
            Some(CPU { ptr })
        }
    }


    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn cpu_from_index(&self, index: usize) -> CPU {
        unsafe {
            CPU {
                ptr: libafl_qemu_get_cpu(index as i32),
            }
        }
    }

    #[must_use]
    pub fn page_from_addr(&self, addr: GuestAddr) -> GuestAddr {
        unsafe { libafl_page_from_addr(addr) }
    }

    //#[must_use]
    /*pub fn page_size() -> GuestUsize {
        unsafe { libafl_page_size }
    }*/

    pub unsafe fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .write_mem(addr, buf);
    }

    pub unsafe fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .read_mem(addr, buf);
    }

    #[must_use]
    pub fn num_regs(&self) -> i32 {
        self.current_cpu().unwrap().num_regs()
    }

    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), QemuRWError>
    where
        T: Num + PartialOrd + Copy + Into<GuestReg>,
        R: Into<i32> + Clone,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Write))?
            .write_reg(reg, val)
    }

    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, QemuRWError>
    where
        T: Num + PartialOrd + Copy + From<GuestReg>,
        R: Into<i32> + Clone,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Read))?
            .read_reg(reg)
    }

    pub fn set_breakpoint(&self, addr: GuestAddr) {
        unsafe {
            libafl_qemu_set_breakpoint(addr.into());
        }
    }

    pub fn remove_breakpoint(&self, addr: GuestAddr) {
        unsafe {
            libafl_qemu_remove_breakpoint(addr.into());
        }
    }

    pub fn entry_break(&self, addr: GuestAddr) {
        self.set_breakpoint(addr);
        unsafe {
            match self.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                _ => panic!("Unexpected QEMU exit."),
            }
        }
        self.remove_breakpoint(addr);
    }

    pub fn flush_jit(&self) {
        unsafe {
            libafl_flush_jit();
        }
    }

    #[must_use]
    pub fn remove_hook(&self, id: impl HookId, invalidate_block: bool) -> bool {
        id.remove(invalidate_block)
    }

    #[allow(clippy::type_complexity)]
    pub fn add_gdb_cmd(&self, callback: Box<dyn FnMut(&Self, &str) -> bool>) {
        unsafe {
            let fat: Box<FatPtr> = Box::new(transmute::<
                Box<dyn for<'a, 'b> FnMut(&'a Qemu, &'b str) -> bool>,
                FatPtr,
            >(callback));
            libafl_qemu_add_gdb_cmd(gdb_cmd, ptr::from_ref(&*fat) as *const ());
            GDB_COMMANDS.push(fat);
        }
    }

    pub fn gdb_reply(&self, output: &str) {
        unsafe { libafl_qemu_gdb_reply(output.as_bytes().as_ptr(), output.len()) };
    }

    #[must_use]
    pub fn host_page_size(&self) -> usize {
        unsafe { libafl_qemu_sys::libafl_qemu_host_page_size() }
    }
}

impl ArchExtras for Qemu {
    fn read_return_address<T>(&self) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>,
    {
        self.current_cpu()
            .ok_or(QemuRWError {
                kind: QemuRWErrorKind::Read,
                cause: QemuRWErrorCause::CurrentCpuNotFound,
                cpu: None,
            })?
            .read_return_address::<T>()
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Write))?
            .write_return_address::<T>(val)
    }

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Read))?
            .read_function_argument::<T>(conv, idx)
    }

    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Write))?
            .write_function_argument::<T>(conv, idx, val)
    }
}

// TODO: maybe include QEMU in the memory chunk to enable address translation and a more accurate implementation
impl PartialEq<Self> for GuestAddrKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (GuestAddrKind::Physical(paddr_self), GuestAddrKind::Physical(paddr_other)) => {
                paddr_self == paddr_other
            }
            (GuestAddrKind::Virtual(vaddr_self), GuestAddrKind::Virtual(vaddr_other)) => {
                vaddr_self == vaddr_other
            }
            _ => false,
        }
    }
}

// TODO: Check PartialEq comment, same idea
impl PartialOrd for GuestAddrKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (GuestAddrKind::Physical(paddr_self), GuestAddrKind::Physical(paddr_other)) => {
                paddr_self.partial_cmp(paddr_other)
            }
            (GuestAddrKind::Virtual(vaddr_self), GuestAddrKind::Virtual(vaddr_other)) => {
                vaddr_self.partial_cmp(vaddr_other)
            }
            _ => None,
        }
    }
}

impl QemuMemoryChunk {
    #[must_use]
    pub fn addr(&self) -> GuestAddrKind {
        self.addr
    }

    #[must_use]
    pub fn size(&self) -> GuestReg {
        self.size
    }

    #[must_use]
    pub fn phys(addr: GuestPhysAddr, size: GuestReg, cpu: Option<CPU>) -> Self {
        Self {
            addr: GuestAddrKind::Physical(addr),
            size,
            cpu,
        }
    }

    #[must_use]
    pub fn virt(addr: GuestVirtAddr, size: GuestReg, cpu: CPU) -> Self {
        Self {
            addr: GuestAddrKind::Virtual(addr),
            size,
            cpu: Some(cpu),
        }
    }

    #[must_use]
    pub fn get_slice(&self, range: &Range<GuestAddr>) -> Option<QemuMemoryChunk> {
        let new_addr = self.addr + range.start;
        let slice_size = range.clone().count();

        if new_addr + (slice_size as GuestUsize) >= self.addr + self.size.into() {
            return None;
        }

        Some(Self {
            addr: new_addr,
            size: slice_size as GuestReg,
            cpu: self.cpu,
        })
    }

    /// Returns the number of bytes effectively written.
    #[must_use]
    pub fn write(&self, qemu: Qemu, input: &[u8]) -> GuestReg {
        let max_len: usize = self.size.try_into().unwrap();

        let input_sliced = if input.len() > max_len {
            &input[0..max_len]
        } else {
            input
        };

        match self.addr {
            GuestAddrKind::Physical(hwaddr) => unsafe {
                #[cfg(emulation_mode = "usermode")]
                {
                    // For now the default behaviour is to fall back to virtual addresses
                    qemu.write_mem(hwaddr.try_into().unwrap(), input_sliced);
                }
                #[cfg(emulation_mode = "systemmode")]
                {
                    qemu.write_phys_mem(hwaddr, input_sliced);
                }
            },
            GuestAddrKind::Virtual(vaddr) => unsafe {
                self.cpu
                    .as_ref()
                    .unwrap()
                    .write_mem(vaddr.try_into().unwrap(), input_sliced);
            },
        };

        input_sliced.len().try_into().unwrap()
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use pyo3::{exceptions::PyValueError, prelude::*};

    use super::{GuestAddr, GuestUsize};

    static mut PY_GENERIC_HOOKS: Vec<(GuestAddr, PyObject)> = vec![];

    extern "C" fn py_generic_hook_wrapper(idx: u64, _pc: GuestAddr) {
        let obj = unsafe { &PY_GENERIC_HOOKS[idx as usize].1 };
        Python::with_gil(|py| {
            obj.call0(py).expect("Error in the hook");
        });
    }

    #[pyclass(unsendable)]
    pub struct Qemu {
        pub qemu: super::Qemu,
    }

    #[pymethods]
    impl Qemu {
        #[allow(clippy::needless_pass_by_value)]
        #[new]
        fn new(args: Vec<String>, env: Vec<(String, String)>) -> PyResult<Qemu> {
            let qemu = super::Qemu::init(&args, &env)
                .map_err(|e| PyValueError::new_err(format!("{e}")))?;

            Ok(Qemu { qemu })
        }

        fn run(&self) {
            unsafe {
                self.qemu.run().unwrap();
            }
        }

        fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
            unsafe {
                self.qemu.write_mem(addr, buf);
            }
        }

        fn read_mem(&self, addr: GuestAddr, size: usize) -> Vec<u8> {
            let mut buf = vec![0; size];
            unsafe {
                self.qemu.read_mem(addr, &mut buf);
            }
            buf
        }

        fn num_regs(&self) -> i32 {
            self.qemu.num_regs()
        }

        fn write_reg(&self, reg: i32, val: GuestUsize) -> PyResult<()> {
            self.qemu
                .write_reg(reg, val)
                .map_err(|_| PyValueError::new_err("write register error"))
        }

        fn read_reg(&self, reg: i32) -> PyResult<GuestUsize> {
            self.qemu
                .read_reg(reg)
                .map_err(|_| PyValueError::new_err("read register error"))
        }

        fn set_breakpoint(&self, addr: GuestAddr) {
            self.qemu.set_breakpoint(addr);
        }

        fn entry_break(&self, addr: GuestAddr) {
            self.qemu.entry_break(addr);
        }

        fn remove_breakpoint(&self, addr: GuestAddr) {
            self.qemu.remove_breakpoint(addr);
        }

        fn flush_jit(&self) {
            self.qemu.flush_jit();
        }

        fn set_hook(&self, addr: GuestAddr, hook: PyObject) {
            unsafe {
                let idx = PY_GENERIC_HOOKS.len();
                PY_GENERIC_HOOKS.push((addr, hook));
                self.qemu.hooks().add_instruction_hooks(
                    idx as u64,
                    addr,
                    py_generic_hook_wrapper,
                    true,
                );
            }
        }

        fn remove_hooks_at(&self, addr: GuestAddr) -> usize {
            unsafe {
                PY_GENERIC_HOOKS.retain(|(a, _)| *a != addr);
            }
            self.qemu.hooks().remove_instruction_hooks_at(addr, true)
        }
    }
}
