use log::info;
use once_cell::sync::Lazy;
use rand::seq::index;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fs::File;
use std::io::{Read, Write};
use std::{path::PathBuf, process};
use std::collections::HashMap;
use std::sync::Mutex;
use std::ptr;

use std::{
    borrow::Cow,
    fmt::{Debug, Formatter},
    marker::PhantomData,
};
use libafl_bolts::{
    current_time, impl_serdeany, tuples::{Handle, Handled, MatchNameRef}
};
use libafl::{
    inputs::{BytesInput, MultipartInput},
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackFactory},
    inputs::Input,
    observers::ObserversTuple,
    state::State,
};
use libafl::prelude::HasCurrentTestcase;
use libafl::prelude::HasCorpus;
use libafl::prelude::HasStartTime;

use libafl_bolts::{Error, Named};

#[derive(Serialize, Deserialize)]
struct SmiGroupInfo {
    info : HashMap<u8, Vec<u8>>,
}

static SMI_GROUPS: Lazy<Mutex<SmiGroupInfo>> = Lazy::new(|| {
    Mutex::new(
        SmiGroupInfo {
            info : HashMap::new()
        })
});


static FUZZER_START_TIME: Lazy<u128> = Lazy::new(|| {
    current_time().as_micros() -  10 * 1000000
});

pub fn add_smi_group_info(group: u8, smi_index: u8) {
    if !SMI_GROUPS.lock().unwrap().info.entry(group).or_insert(vec![]).contains(&smi_index) {
        SMI_GROUPS.lock().unwrap().info.entry(group).or_insert(vec![]).push(smi_index);
    }
}
pub fn get_smi_by_random_group_index(group: u8, random_index: u8) -> Option<u8> {
    let group = group %  SMI_GROUPS.lock().unwrap().info.len() as u8;
    SMI_GROUPS.lock().unwrap().info.get(&group).and_then(|v| v.get((random_index % v.len() as u8) as usize).copied())
}

pub fn smi_group_info_to_file(filename : &PathBuf) {
    let file = File::create(filename).unwrap();
    serde_json::to_writer(file, &*SMI_GROUPS.lock().unwrap() ).unwrap();
}

pub fn smi_group_info_from_file(filename : &PathBuf) {
    let mut file = File::open(filename).unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();

    let mut info : SmiGroupInfo = serde_json::from_str(&buffer).unwrap();
    
    let mut smi_groups_lock = SMI_GROUPS.lock().unwrap(); // Lock the Mutex to get access

    *smi_groups_lock = info;
}
pub fn get_num_smi_group() -> usize {
    unsafe {
        SMI_GROUPS.lock().unwrap().info.len()
    }
}

#[derive(Serialize, Deserialize)]
pub struct SmiGlobalFoundTimeMetadataFeedback;

impl<S> Feedback<S> for SmiGlobalFoundTimeMetadataFeedback
where
    S: HasCurrentTestcase<MultipartInput<BytesInput>> + State<Input = MultipartInput<BytesInput>> + HasCorpus<Input = MultipartInput<BytesInput>> + HasStartTime,
{
    fn append_metadata<EM, OT>(
            &mut self,
            state: &mut S,
            manager: &mut EM,
            observers: &OT,
            testcase: &mut Testcase<<S>::Input>,
        ) -> Result<(), Error>
        where
            OT: ObserversTuple<S>,
            EM: EventFirer<State = S>, {
        testcase.set_found_time(current_time().as_micros() - unsafe {*FUZZER_START_TIME});
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &<S>::Input) -> Result<(), Error> {
        Ok(())
    }

    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
    fn is_interesting<EM, OT>(
            &mut self,
            state: &mut S,
            manager: &mut EM,
            input: &<S>::Input,
            observers: &OT,
            exit_kind: &ExitKind,
        ) -> Result<bool, Error>
        where
            EM: EventFirer<State = S>,
            OT: ObserversTuple<S> {
        Ok(false)
    }
}

impl Named for SmiGlobalFoundTimeMetadataFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SmiGlobalFoundTimeMetadataFeedback")
    }
}

impl SmiGlobalFoundTimeMetadataFeedback {
    #[must_use]
    pub fn new() -> Self {
        SmiGlobalFoundTimeMetadataFeedback
    }
}
