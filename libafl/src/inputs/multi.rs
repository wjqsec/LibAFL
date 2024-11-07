//! Definitions for inputs which have multiple distinct subcomponents.
//!
//! Unfortunately, since both [`serde::de::Deserialize`] and [`Clone`] require [`Sized`], it is not
//! possible to dynamically define a single input with dynamic typing. As such, [`MultipartInput`]
//! requires that each subcomponent be the same subtype.

use core::hash::{Hash, Hasher};
use std::string::ToString;
use crate::prelude::std::hash::DefaultHasher;
use alloc::{
    string::String,
    vec::Vec,
};

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

use crate::{corpus::CorpusId, inputs::Input};

/// An input composed of multiple parts. Use in situations where subcomponents are not necessarily
/// related, or represent distinct parts of the input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultipartInput<I> {
    ids: Vec<u128>,
    parts: Vec<I>,
    limits : Vec<usize>,
}

impl<I> Default for MultipartInput<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> MultipartInput<I> {
    /// Create a new multipart input.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parts: Vec::new(),
            ids: Vec::new(),
            limits : Vec::new(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
    //remove a stream
    pub fn remove_part(&mut self, id : &u128) {
        let mut index_to_remove = Vec::new();
        for i in 0..self.ids.len() {
            if self.ids[i] == *id {
                index_to_remove.push(i);
            }
        }
        for index in index_to_remove {
            self.ids.remove(index);
            self.parts.remove(index);
            self.limits.remove(index);
        }
        
    }
    fn idxs_to_skips(idxs: &mut [usize]) {
        for following in (1..idxs.len()).rev() {
            let first = idxs[following - 1];
            let second = idxs[following];

            idxs[following] = second
                .checked_sub(first)
                .expect("idxs was not sorted")
                .checked_sub(1)
                .expect("idxs had duplicate elements");
        }
    }

    /// Get the individual parts of this input.
    #[must_use]
    pub fn parts(&self) -> &[I] {
        &self.parts
    }

    #[must_use]
    pub fn part_by_id(&self, id : &u128) -> &I {
        if let Some(index) = self.ids.iter().position(|&x| x == *id) {
            &self.parts[index]
        } else {
            panic!("part by id, id not found\n");
        }
    }
    #[must_use]
    pub fn part_by_id_mut(&mut self, id : &u128) -> &mut I {
        if let Some(index) = self.ids.iter().position(|&x| x == *id) {
            &mut self.parts[index]
        } else {
            panic!("part by id mut, id not found\n");
        }
    }


    /// Access multiple parts mutably.
    ///
    /// ## Panics
    ///
    /// Panics if idxs is not sorted, has duplicate elements, or any entry is out of bounds.
    #[must_use]
    pub fn parts_mut<const N: usize>(&mut self, mut idxs: [usize; N]) -> [&mut I; N] {
        Self::idxs_to_skips(&mut idxs);

        let mut parts = self.parts.iter_mut();
        if let Ok(arr) = idxs
            .into_iter()
            .map(|i| parts.nth(i).expect("idx had an out of bounds entry"))
            .collect::<ArrayVec<_, N>>()
            .into_inner()
        {
            arr
        } else {
            // avoid Debug trait requirement for expect/unwrap
            panic!("arrayvec collection failed somehow")
        }
    }

    /// Get a specific part of this input by index.
    pub fn part_mut(&mut self, idx: usize) -> Option<&mut I> {
        self.parts.get_mut(idx)
    }

    pub fn part_limit(&self, idx : usize) -> usize {
        self.limits.get(idx).unwrap().clone()
    }

    /// Get the ids associated with the subparts of this input. Used to distinguish between the
    /// input components in the case where some parts may or may not be present, or in different
    /// orders.
    #[must_use]
    pub fn names(&self) -> &[u128] {
        &self.ids
    }
    #[must_use]
    pub fn limits(&self) -> &[usize] {
        &self.limits
    }
    /// Gets a reference to each part with the provided id.
    pub fn parts_by_name<'a, 'b>(
        &'b self,
        id: &'a u128,
    ) -> impl Iterator<Item = (usize, &'b I)> + 'a
    where
        'b: 'a,
    {
        self.names()
            .iter()
            .zip(&self.parts)
            .enumerate()
            .filter_map(move |(i, (s, item))| (*s == *id).then_some((i, item)))
    }

    /// Gets a mutable reference to each part with the provided id.
    pub fn parts_by_name_mut<'a, 'b>(
        &'b mut self,
        id: &'a u128,
    ) -> impl Iterator<Item = (usize, &'b mut I)> + 'a
    where
        'b: 'a,
    {
        self.ids
            .iter()
            .zip(&mut self.parts)
            .enumerate()
            .filter_map(move |(i, (s, item))| (*s == *id).then_some((i, item)))
    }

    /// Adds a part to this input, potentially with the same id as an existing part.
    pub fn add_part(&mut self, id: u128, part: I, limit : usize) {
        if self.ids.contains(&id) {
            panic!("multi input does not support multiple same id inputs");
        }
        self.ids.push(id);
        self.parts.push(part);
        self.limits.push(limit);
    }

    /// Iterate over the parts of this input; no order is specified.
    pub fn iter(&self) -> impl Iterator<Item = (&u128, &I)> {
        self.ids.iter().zip(self.parts())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&u128, &mut I)> {
        self.ids.iter().zip(self.parts.iter_mut())
    }
}

impl<I, It, S> From<It> for MultipartInput<I>
where
    It: IntoIterator<Item = (S, I, usize)>,
    S: Into<u128>,
{
    fn from(parts: It) -> Self {
        let mut input = MultipartInput::new();
        for (id, part, limit) in parts {
            input.add_part(id.into(), part, limit);
        }
        input
    }
}

impl<I> Input for MultipartInput<I>
where
    I: Input,
{
    fn generate_name(&self, id: Option<CorpusId>) -> String {
        let mut h = DefaultHasher::new();
        let content = self.ids
            .iter()
            .cloned()
            .zip(self.parts.iter().map(|i| i.generate_name(id)))
            .map(|(id, generated)| format!("{id:#x}-{generated}"))
            .collect::<Vec<_>>()
            .join(",");
        content.hash(&mut h);
        h.finish().to_string()
    }
}