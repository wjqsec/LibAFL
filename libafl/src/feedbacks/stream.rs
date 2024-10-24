use core::{borrow::{Borrow, BorrowMut}, ops::DerefMut};

use alloc::{borrow::Cow, string::String};
use crate::{corpus::Corpus, prelude::HasCorpus};
use libafl_bolts::{
    impl_serdeany,
    tuples::{Handle, Handled, MatchNameRef},
    Named,
};
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
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // TODO Replace with match_name_type when stable
        let observer = observers.get(&self.observer_handle).unwrap();
        if observer.has_newstream() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
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
        let observer = observers.get(&self.observer_handle).unwrap();
        if observer.has_newstream() {
            let n_all = state.corpus().count_all();
            for i in 0..n_all {
                let idx = state.corpus().nth_from_all(i);
                for new_stream in observer.get_newstream().into_iter() {
                    state.corpus().get(idx).and_then( | t | 
                    Ok(t.borrow_mut().input_mut().as_mut().unwrap().add_part(new_stream, BytesInput::new(vec![0x00,0x00,0x00,0x00])))).unwrap();
                }
            }
            for new_stream in observer.get_newstream().into_iter() {
                testcase.input_mut().as_mut().unwrap().add_part(new_stream, BytesInput::new(vec![0x00,0x00,0x00,0x00]));
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