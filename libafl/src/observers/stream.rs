use alloc::{borrow::Cow, boxed::Box, vec::Vec};
use core::{
    borrow::BorrowMut, cell::{Ref, RefCell, RefMut}, fmt::Debug, hash::{Hash, Hasher}, ops::{Deref, DerefMut}
};

use ahash::RandomState;
use libafl_bolts::{ownedref::OwnedRef, AsIter, AsIterMut, AsSlice, AsSliceMut, Named};
use serde::{Deserialize, Serialize};

use super::Observer;
use crate::{inputs::UsesInput, observers::ObserverWithHashField, Error};
use alloc::sync::Arc;
use crate::prelude::std::sync::Mutex;
use crate::prelude::ExitKind;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StreamObserver {
    name: Cow<'static, str>,
    new_stream : Arc<Mutex<Vec<u128>>>,
}

impl StreamObserver {
    #[must_use]
    pub fn new(name: &'static str, new_stream : Arc<Mutex<Vec<u128>>>) -> Self {
        Self {
            name: Cow::from(name),
            new_stream,
        }
    }
    pub fn get_newstream(&self) -> Vec<u128> {
        self.new_stream.lock().unwrap().clone()
    }
    pub fn has_newstream(&self) -> bool {
        !self.new_stream.lock().unwrap().is_empty()
    }
}

impl<S> Observer<S> for StreamObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.new_stream.lock().unwrap().clear();
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

impl Named for StreamObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}