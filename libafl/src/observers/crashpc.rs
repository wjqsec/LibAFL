use alloc::{borrow::Cow, boxed::Box, vec::Vec};
use core::{
    borrow::BorrowMut, cell::{Ref, RefCell, RefMut}, fmt::Debug, hash::{Hash, Hasher}, ops::{Deref, DerefMut}
};

use ahash::RandomState;
use libafl_bolts::{ownedref::OwnedRef, AsIter, AsIterMut, AsSlice, AsSliceMut, Named};
use serde::{Deserialize, Serialize};
use std::string::String;
use super::Observer;
use crate::{inputs::UsesInput, observers::ObserverWithHashField, Error};
use alloc::sync::Arc;
use crate::prelude::std::sync::Mutex;
use crate::prelude::ExitKind;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CrashpcObserver {
    name: Cow<'static, str>,
    crash_feedback : Arc<Mutex<String>>,
}

impl CrashpcObserver {
    #[must_use]
    pub fn new(name: &'static str, crash_feedback : Arc<Mutex<String>>) -> Self {
        Self {
            name: Cow::from(name),
            crash_feedback,
        }
    }
    pub fn get_last_crashpc(&self) -> String {
        self.crash_feedback.lock().unwrap().clone()
    }
}

impl<S> Observer<S> for CrashpcObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.crash_feedback.lock().unwrap().clear();
        Ok(())
    }
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

}

impl Named for CrashpcObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}