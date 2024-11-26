use core::{borrow::{Borrow, BorrowMut}, ops::DerefMut};

use alloc::{borrow::Cow, string::String};
use crate::{corpus::Corpus, inputs::{HasMutatorBytes, HasTargetBytes}, prelude::{minimizer, HasCorpus}};
use libafl_bolts::{
    impl_serdeany,
    tuples::{Handle, Handled, MatchNameRef},
    Named,
};
use std::cmp::min;
use serde::{Deserialize, Serialize};
use crate::prelude::HasCurrentTestcase;
use crate::{
    corpus::Testcase, events::EventFirer, executors::ExitKind, feedbacks::Feedback, inputs::{BytesInput, MultipartInput}, observers::{ObserversTuple, StdErrObserver, StdOutObserver}, state::State, Error, HasMetadata
};
use crate::observers::stream::StreamObserver;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StreamFeedback {
    observer_handle: Handle<StreamObserver>,
}

impl<S> Feedback<S> for StreamFeedback
where
    S: HasCurrentTestcase<MultipartInput<BytesInput>> + State<Input = MultipartInput<BytesInput>> + HasCorpus<Input = MultipartInput<BytesInput>>,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        let observer = observers.get(&self.observer_handle).unwrap();
        for (id, tmp_generated, used, input, limit) in observer.get_newstream().into_iter() {
            if tmp_generated {
                let used_len = min(input.len(), used);
                testcase.input_mut().as_mut().unwrap().add_part(id, BytesInput::new(input[..used_len].to_vec()), limit);
            } else {
                if used == 0 {
                    testcase.input_mut().as_mut().unwrap().remove_part(&id);
                } else {
                    for (_, corpus_input) in testcase.input_mut().as_mut().unwrap().parts_by_name_mut(&id) {
                        let old_len = corpus_input.target_bytes().len();
                        if old_len != used {
                            corpus_input.resize(used, 0);
                        }
                        
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

}

impl Named for StreamFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl StreamFeedback {
    /// Creates a new [`TimeFeedback`], deciding if the given [`TimeObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(observer: &StreamObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
        }
    }
}