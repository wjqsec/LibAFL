use log::info;
use once_cell::sync::Lazy;
use rand::seq::index;
use serde::{Deserialize, Serialize};
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

static mut SMI_GROUPS : *mut SmiGroupInfo = ptr::null_mut();

pub fn init_smi_groups() {
    unsafe {
        SMI_GROUPS = Box::into_raw(Box::new(SmiGroupInfo {
            info : HashMap::new()
        }));
    }
}

pub fn add_smi_group_info(group: u8, smi_index: u8) {
    unsafe {
        if ! (&mut (*SMI_GROUPS)).info.entry(group).or_insert(vec![]).contains(&smi_index) {
            (&mut (*SMI_GROUPS)).info.entry(group).or_insert(vec![]).push(smi_index);
        }
    }
}
pub fn get_smi_by_random_group_index(group: u8, random_index: u8) -> Option<u8> {
    unsafe {
        let group = group % (&mut (*SMI_GROUPS)).info.len() as u8;
        (&mut (*SMI_GROUPS)).info.get(&group).and_then(|v| v.get((random_index % v.len() as u8) as usize).copied())
    }
}

pub fn smi_group_info_to_file(filename : &PathBuf) {
    let file = File::create(filename).unwrap();
    serde_json::to_writer(file, unsafe { &*SMI_GROUPS } ).unwrap();
}

pub fn smi_group_info_from_file(filename : &PathBuf) {
    let mut file = File::open(filename).unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();

    let mut info : SmiGroupInfo = serde_json::from_str(&buffer).unwrap();
    
    unsafe {
        if !SMI_GROUPS.is_null() {
            let _ = Box::from_raw(SMI_GROUPS);
        }
        SMI_GROUPS = Box::into_raw(Box::new(info));
    }
}

// #[derive(Serialize, Deserialize)]
// pub struct SmiMetadataFileFeedback;

// impl<S> Feedback<S> for SmiMetadataFileFeedback
// where
//     S: HasCurrentTestcase<MultipartInput<BytesInput>> + State<Input = MultipartInput<BytesInput>> + HasCorpus<Input = MultipartInput<BytesInput>> + HasStartTime,
// {
//     fn append_metadata<EM, OT>(
//             &mut self,
//             state: &mut S,
//             manager: &mut EM,
//             observers: &OT,
//             testcase: &mut Testcase<<S>::Input>,
//         ) -> Result<(), Error>
//         where
//             OT: ObserversTuple<S>,
//             EM: EventFirer<State = S>, {
//         let smi_metadata_filename = format!(".{}.smi_metadata",testcase.filename().clone().unwrap());
//         let smi_metadata_fullpath = PathBuf::from(testcase.file_path().clone().unwrap()).parent().unwrap().join(smi_metadata_filename.clone());
//         smi_group_info_to_file(&smi_metadata_fullpath);
//         Ok(())
//     }

//     fn discard_metadata(&mut self, _state: &mut S, _input: &<S>::Input) -> Result<(), Error> {
//         Ok(())
//     }

//     fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
//         Ok(())
//     }
//     fn is_interesting<EM, OT>(
//             &mut self,
//             state: &mut S,
//             manager: &mut EM,
//             input: &<S>::Input,
//             observers: &OT,
//             exit_kind: &ExitKind,
//         ) -> Result<bool, Error>
//         where
//             EM: EventFirer<State = S>,
//             OT: ObserversTuple<S> {
//         Ok(false)
//     }
// }

// impl Named for SmiMetadataFileFeedback {
//     #[inline]
//     fn name(&self) -> &Cow<'static, str> {
//         &Cow::Borrowed("SmiMetadataFileFeedback")
//     }
// }

// impl SmiMetadataFileFeedback {
//     /// Creates a new [`TimeFeedback`], deciding if the given [`TimeObserver`] value of a run is interesting.
//     #[must_use]
//     pub fn new() -> Self {
//         SmiMetadataFileFeedback
//     }
// }
