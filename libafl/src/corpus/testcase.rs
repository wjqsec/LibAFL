//! The [`Testcase`] is a struct embedded in each [`Corpus`].
//! It will contain a respective input, and metadata.

use alloc::string::String;
#[cfg(feature = "track_hit_feedbacks")]
use alloc::{borrow::Cow, vec::Vec};
use core::{
    cell::{Ref, RefMut},
    time::Duration,
};
#[cfg(feature = "std")]
use std::path::PathBuf;

use libafl_bolts::{serdeany::SerdeAnyMap, HasLen};
use serde::{Deserialize, Serialize};

use super::Corpus;
use crate::{
    corpus::CorpusId,
    inputs::{Input, UsesInput},
    Error, HasMetadata,
};

/// Shorthand to receive a [`Ref`] or [`RefMut`] to a stored [`Testcase`], by [`CorpusId`].
/// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
pub trait HasTestcase: UsesInput {
    /// Shorthand to receive a [`Ref`] to a stored [`Testcase`], by [`CorpusId`].
    /// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
    fn testcase(&self, id: CorpusId) -> Result<Ref<Testcase<<Self as UsesInput>::Input>>, Error>;

    /// Shorthand to receive a [`RefMut`] to a stored [`Testcase`], by [`CorpusId`].
    /// For a normal state, this should return a [`Testcase`] in the corpus, not the objectives.
    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<RefMut<Testcase<<Self as UsesInput>::Input>>, Error>;
}

/// An entry in the [`Testcase`] Corpus
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct Testcase<I>
where
    I: Input,
{
    /// The [`Input`] of this [`Testcase`], or `None`, if it is not currently in memory
    input: Option<I>,
    /// The filename for this [`Testcase`]
    filename: Option<String>,
    /// Complete path to the [`Input`] on disk, if this [`Testcase`] is backed by a file in the filesystem
    #[cfg(feature = "std")]
    file_path: Option<PathBuf>,
    /// Map of metadata associated with this [`Testcase`]
    metadata: SerdeAnyMap,
    /// Complete path to the metadata [`SerdeAnyMap`] on disk, if this [`Testcase`] is backed by a file in the filesystem
    #[cfg(feature = "std")]
    metadata_path: Option<PathBuf>,
    /// Time needed to execute the input
    exec_time: Option<Duration>,
    /// Time needed to found the input
    found_time: u128,
    /// Cached len of the input, if any
    cached_len: Option<usize>,
    /// Number of executions done at discovery time
    executions: u64,
    /// Number of fuzzing iterations of this particular input updated in `perform_mutational`
    scheduled_count: usize,
    /// Parent [`CorpusId`], if known
    parent_id: Option<CorpusId>,
    /// If the testcase is "disabled"
    disabled: bool,
    /// has found crash (or timeout) or not
    objectives_found: usize,
    /// Vector of `Feedback` names that deemed this `Testcase` as corpus worthy
    #[cfg(feature = "track_hit_feedbacks")]
    hit_feedbacks: Vec<Cow<'static, str>>,
    /// Vector of `Feedback` names that deemed this `Testcase` as solution worthy
    #[cfg(feature = "track_hit_feedbacks")]
    hit_objectives: Vec<Cow<'static, str>>,
}

impl<I> HasMetadata for Testcase<I>
where
    I: Input,
{
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

/// Impl of a testcase
impl<I> Testcase<I>
where
    I: Input,
{
    /// Returns this [`Testcase`] with a loaded `Input`]
    pub fn load_input<C: Corpus<Input = I>>(&mut self, corpus: &C) -> Result<&I, Error> {
        corpus.load_input_into(self)?;
        Ok(self.input.as_ref().unwrap())
    }

    /// Get the input, if available any
    #[inline]
    pub fn input(&self) -> &Option<I> {
        &self.input
    }

    /// Get the input, if any (mutable)
    #[inline]
    pub fn input_mut(&mut self) -> &mut Option<I> {
        // self.cached_len = None;
        &mut self.input
    }

    /// Set the input
    #[inline]
    pub fn set_input(&mut self, mut input: I) {
        input.wrapped_as_testcase();
        self.input = Some(input);
    }

    /// Get the filename, if any
    #[inline]
    pub fn filename(&self) -> &Option<String> {
        &self.filename
    }

    /// Get the filename, if any (mutable)
    #[inline]
    pub fn filename_mut(&mut self) -> &mut Option<String> {
        &mut self.filename
    }

    /// Get the filename path, if any
    #[inline]
    #[cfg(feature = "std")]
    pub fn file_path(&self) -> &Option<PathBuf> {
        &self.file_path
    }

    /// Get the filename path, if any (mutable)
    #[inline]
    #[cfg(feature = "std")]
    pub fn file_path_mut(&mut self) -> &mut Option<PathBuf> {
        &mut self.file_path
    }

    /// Get the metadata path, if any
    #[inline]
    #[cfg(feature = "std")]
    pub fn metadata_path(&self) -> &Option<PathBuf> {
        &self.metadata_path
    }

    /// Get the metadata path, if any (mutable)
    #[inline]
    #[cfg(feature = "std")]
    pub fn metadata_path_mut(&mut self) -> &mut Option<PathBuf> {
        &mut self.metadata_path
    }

    /// Get the execution time of the testcase
    #[inline]
    pub fn exec_time(&self) -> &Option<Duration> {
        &self.exec_time
    }

    /// Get the execution time of the testcase (mutable)
    #[inline]
    pub fn exec_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.exec_time
    }

    /// Sets the execution time of the current testcase
    #[inline]
    pub fn set_exec_time(&mut self, time: Duration) {
        self.exec_time = Some(time);
    }

    /// Get the execution time of the testcase
    #[inline]
    pub fn found_time(&self) -> &u128 {
        &self.found_time
    }

    /// Get the execution time of the testcase (mutable)
    #[inline]
    pub fn found_time_mut(&mut self) -> &mut u128 {
        &mut self.found_time
    }

    /// Sets the execution time of the current testcase
    #[inline]
    pub fn set_found_time(&mut self, time: u128) {
        self.found_time = time;
    }

    /// Get the executions
    #[inline]
    pub fn executions(&self) -> &u64 {
        &self.executions
    }

    /// Get the executions (mutable)
    #[inline]
    pub fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }

    /// Get the `scheduled_count`
    #[inline]
    pub fn scheduled_count(&self) -> usize {
        self.scheduled_count
    }

    /// Set the `scheduled_count`
    #[inline]
    pub fn set_scheduled_count(&mut self, scheduled_count: usize) {
        self.scheduled_count = scheduled_count;
    }

    /// Get `disabled`
    #[inline]
    pub fn disabled(&mut self) -> bool {
        self.disabled
    }

    /// Set the testcase as disabled
    #[inline]
    pub fn set_disabled(&mut self, disabled: bool) {
        self.disabled = disabled;
    }

    /// Get the hit feedbacks
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_feedbacks(&self) -> &Vec<Cow<'static, str>> {
        &self.hit_feedbacks
    }

    /// Get the hit feedbacks (mutable)
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_feedbacks_mut(&mut self) -> &mut Vec<Cow<'static, str>> {
        &mut self.hit_feedbacks
    }

    /// Get the hit objectives
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_objectives(&self) -> &Vec<Cow<'static, str>> {
        &self.hit_objectives
    }

    /// Get the hit objectives (mutable)
    #[inline]
    #[cfg(feature = "track_hit_feedbacks")]
    pub fn hit_objectives_mut(&mut self) -> &mut Vec<Cow<'static, str>> {
        &mut self.hit_objectives
    }

    /// Create a new Testcase instance given an input
    #[inline]
    pub fn new(mut input: I) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: None,
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            found_time: 0,
            cached_len: None,
            executions: 0,
            scheduled_count: 0,
            parent_id: None,
            disabled: false,
            objectives_found: 0,
            #[cfg(feature = "track_hit_feedbacks")]
            hit_feedbacks: Vec::new(),
            #[cfg(feature = "track_hit_feedbacks")]
            hit_objectives: Vec::new(),
        }
    }

    /// Creates a testcase, attaching the id of the parent
    /// that this [`Testcase`] was derived from on creation
    pub fn with_parent_id(mut input: I, parent_id: CorpusId) -> Self {
        input.wrapped_as_testcase();
        Testcase {
            input: Some(input),
            filename: None,
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            found_time: 0,
            cached_len: None,
            executions: 0,
            scheduled_count: 0,
            parent_id: Some(parent_id),
            disabled: false,
            objectives_found: 0,
            #[cfg(feature = "track_hit_feedbacks")]
            hit_feedbacks: Vec::new(),
            #[cfg(feature = "track_hit_feedbacks")]
            hit_objectives: Vec::new(),
        }
    }

    /// Create a new Testcase instance given an [`Input`] and a `filename`
    #[inline]
    pub fn with_filename(mut input: I, filename: String) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: Some(filename),
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            found_time: 0,
            cached_len: None,
            executions: 0,
            scheduled_count: 0,
            parent_id: None,
            disabled: false,
            objectives_found: 0,
            #[cfg(feature = "track_hit_feedbacks")]
            hit_feedbacks: Vec::new(),
            #[cfg(feature = "track_hit_feedbacks")]
            hit_objectives: Vec::new(),
        }
    }

    /// Create a new Testcase instance given an [`Input`] and the number of executions
    #[inline]
    pub fn with_executions(mut input: I, executions: u64) -> Self {
        input.wrapped_as_testcase();
        Self {
            input: Some(input),
            filename: None,
            #[cfg(feature = "std")]
            file_path: None,
            metadata: SerdeAnyMap::default(),
            #[cfg(feature = "std")]
            metadata_path: None,
            exec_time: None,
            found_time: 0,
            cached_len: None,
            executions,
            scheduled_count: 0,
            parent_id: None,
            disabled: false,
            objectives_found: 0,
            #[cfg(feature = "track_hit_feedbacks")]
            hit_feedbacks: Vec::new(),
            #[cfg(feature = "track_hit_feedbacks")]
            hit_objectives: Vec::new(),
        }
    }

    /// Get the id of the parent, that this testcase was derived from
    #[must_use]
    pub fn parent_id(&self) -> Option<CorpusId> {
        self.parent_id
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id(&mut self, parent_id: CorpusId) {
        self.parent_id = Some(parent_id);
    }

    /// Sets the id of the parent, that this testcase was derived from
    pub fn set_parent_id_optional(&mut self, parent_id: Option<CorpusId>) {
        self.parent_id = parent_id;
    }

    /// Gets how many objectives were found by mutating this testcase
    pub fn objectives_found(&self) -> usize {
        self.objectives_found
    }

    /// Adds one objectives to the `objectives_found` counter. Mostly called from crash handler or executor.
    pub fn found_objective(&mut self) {
        self.objectives_found = self.objectives_found.saturating_add(1);
    }
}

impl<I> Default for Testcase<I>
where
    I: Input,
{
    /// Create a new default Testcase
    #[inline]
    fn default() -> Self {
        Testcase {
            input: None,
            filename: None,
            metadata: SerdeAnyMap::new(),
            exec_time: None,
            found_time: 0,
            cached_len: None,
            scheduled_count: 0,
            executions: 0,
            parent_id: None,
            #[cfg(feature = "std")]
            file_path: None,
            #[cfg(feature = "std")]
            metadata_path: None,
            disabled: false,
            objectives_found: 0,
            #[cfg(feature = "track_hit_feedbacks")]
            hit_feedbacks: Vec::new(),
            #[cfg(feature = "track_hit_feedbacks")]
            hit_objectives: Vec::new(),
        }
    }
}

/// Impl of a testcase when the input has len
impl<I> Testcase<I>
where
    I: Input + HasLen,
{
    /// Get the cached `len`. Will `Error::EmptyOptional` if `len` is not yet cached.
    #[inline]
    pub fn cached_len(&mut self) -> Option<usize> {
        self.cached_len
    }

    /// Get the `len` or calculate it, if not yet calculated.
    #[allow(clippy::len_without_is_empty)]
    pub fn load_len<C: Corpus<Input = I>>(&mut self, corpus: &C) -> Result<usize, Error> {
        match &self.input {
            Some(i) => {
                let l = i.len();
                self.cached_len = Some(l);
                Ok(l)
            }
            None => {
                if let Some(l) = self.cached_len {
                    Ok(l)
                } else {
                    corpus.load_input_into(self)?;
                    self.load_len(corpus)
                }
            }
        }
    }
}

/// Create a testcase from an input
impl<I> From<I> for Testcase<I>
where
    I: Input,
{
    fn from(input: I) -> Self {
        Testcase::new(input)
    }
}

/// The Metadata for each testcase used in power schedules.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct SchedulerTestcaseMetadata {
    /// Number of bits set in bitmap, updated in `calibrate_case`
    bitmap_size: u64,
    /// Number of queue cycles behind
    handicap: u64,
    /// Path depth, initialized in `on_add`
    depth: u64,
    /// Offset in `n_fuzz`
    n_fuzz_entry: usize,
    /// Cycles used to calibrate this (not really needed if it were not for `on_replace` and `on_remove`)
    cycle_and_time: (Duration, usize),
}

impl SchedulerTestcaseMetadata {
    /// Create new [`struct@SchedulerTestcaseMetadata`]
    #[must_use]
    pub fn new(depth: u64) -> Self {
        Self {
            bitmap_size: 0,
            handicap: 0,
            depth,
            n_fuzz_entry: 0,
            cycle_and_time: (Duration::default(), 0),
        }
    }

    /// Create new [`struct@SchedulerTestcaseMetadata`] given `n_fuzz_entry`
    #[must_use]
    pub fn with_n_fuzz_entry(depth: u64, n_fuzz_entry: usize) -> Self {
        Self {
            bitmap_size: 0,
            handicap: 0,
            depth,
            n_fuzz_entry,
            cycle_and_time: (Duration::default(), 0),
        }
    }

    /// Get the bitmap size
    #[inline]
    #[must_use]
    pub fn bitmap_size(&self) -> u64 {
        self.bitmap_size
    }

    /// Set the bitmap size
    #[inline]
    pub fn set_bitmap_size(&mut self, val: u64) {
        self.bitmap_size = val;
    }

    /// Get the handicap
    #[inline]
    #[must_use]
    pub fn handicap(&self) -> u64 {
        self.handicap
    }

    /// Set the handicap
    #[inline]
    pub fn set_handicap(&mut self, val: u64) {
        self.handicap = val;
    }

    /// Get the depth
    #[inline]
    #[must_use]
    pub fn depth(&self) -> u64 {
        self.depth
    }

    /// Set the depth
    #[inline]
    pub fn set_depth(&mut self, val: u64) {
        self.depth = val;
    }

    /// Get the `n_fuzz_entry`
    #[inline]
    #[must_use]
    pub fn n_fuzz_entry(&self) -> usize {
        self.n_fuzz_entry
    }

    /// Set the `n_fuzz_entry`
    #[inline]
    pub fn set_n_fuzz_entry(&mut self, val: usize) {
        self.n_fuzz_entry = val;
    }

    /// Get the cycles
    #[inline]
    #[must_use]
    pub fn cycle_and_time(&self) -> (Duration, usize) {
        self.cycle_and_time
    }

    #[inline]
    /// Setter for cycles
    pub fn set_cycle_and_time(&mut self, cycle_and_time: (Duration, usize)) {
        self.cycle_and_time = cycle_and_time;
    }
}

libafl_bolts::impl_serdeany!(SchedulerTestcaseMetadata);

#[cfg(feature = "std")]
impl<I> Drop for Testcase<I>
where
    I: Input,
{
    fn drop(&mut self) {
        if let Some(filename) = &self.filename {
            let mut path = PathBuf::from(filename);
            let lockname = format!(".{}.lafl_lock", path.file_name().unwrap().to_str().unwrap());
            path.set_file_name(lockname);
            let _ = std::fs::remove_file(path);
        }
    }
}
