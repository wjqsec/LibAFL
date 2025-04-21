use core::{borrow::{Borrow, BorrowMut}, ops::DerefMut};

use alloc::{borrow::Cow, string::String};
use crate::{corpus::Corpus, inputs::{HasMutatorBytes, HasTargetBytes}, observers::crashpc, prelude::{minimizer, HasCorpus}};
use libafl_bolts::{
    current_time, impl_serdeany, tuples::{Handle, Handled, MatchNameRef}, Named
};
use std::{cmp::min, io::Read};
use serde::{Deserialize, Serialize};
use crate::prelude::HasCurrentTestcase;
use crate::{
    corpus::Testcase, events::EventFirer, executors::ExitKind, feedbacks::Feedback, inputs::{BytesInput, MultipartInput}, observers::{ObserversTuple, StdErrObserver, StdOutObserver}, state::State, Error, HasMetadata
};
use std::vec::Vec;
use crate::observers::crashpc::CrashpcObserver;
use crate::prelude::HasStartTime;
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrashpcFeedback {
    observer_handle: Handle<CrashpcObserver>,
    crashpc_history : Vec<String>,
}

impl<S> Feedback<S> for CrashpcFeedback
where
    S: HasCurrentTestcase<MultipartInput<BytesInput>> + State<Input = MultipartInput<BytesInput>> + HasCorpus<Input = MultipartInput<BytesInput>> + HasStartTime,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer = observers.get(&self.observer_handle).unwrap();
        let lastpc = observer.get_last_crashpc();
        if lastpc.is_empty() {
            return Ok(false);
        }
        if self.crashpc_history.contains(&lastpc) {
            return Ok(false);
        }
        self.crashpc_history.push(lastpc);
        return Ok(true);
    }

    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        Ok(())
    }

    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

}

impl Named for CrashpcFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl CrashpcFeedback {

    #[must_use]
    pub fn new(observer: &CrashpcObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
            crashpc_history: Vec::new(),
        }
    }
}