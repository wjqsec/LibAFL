//! Mutator definitions for [`MultipartInput`]s. See [`crate::inputs::multi`] for details.

use core::cmp::{min, Ordering};

use libafl_bolts::{rands::Rand, Error};
use crate::{
    corpus::{Corpus, CorpusId},
    impl_default_multipart,
    inputs::{multi::MultipartInput, HasMutatorBytes, Input},
    mutators::{
        mutations::{
            rand_range, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator,
            ByteIncMutator, ByteInterestingMutator, ByteNegMutator, ByteRandMutator,
            BytesCopyMutator, BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator,
            BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
            BytesSwapMutator, CrossoverInsertMutator, CrossoverReplaceMutator, DwordAddMutator,
            DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
        },
        token_mutations::{I2SRandReplace, TokenInsert, TokenReplace},
        MutationResult, Mutator,
    },
    random_corpus_id,
    state::{HasCorpus, HasMaxSize, HasRand},
};
use crate::prelude::State;
use rand::prelude::*;
use rand::distributions::WeightedIndex;
/// Marker trait for if the default multipart input mutator implementation is appropriate.
///
/// You should implement this type for your mutator if you just want a random part of the input to
/// be selected and mutated. Use [`impl_default_multipart`] to implement this marker trait for many
/// at once.
pub trait DefaultMultipartMutator {}

impl<I, M, S> Mutator<MultipartInput<I>, S> for M
where
    M: DefaultMultipartMutator + Mutator<I, S>,
    S: HasRand + State + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I>,
    ) -> Result<MutationResult, Error> {
        if input.parts().is_empty(){
            Ok(MutationResult::Skipped)
        } else {
            let dist = WeightedIndex::new(input.weights());
            if dist.is_err() {
                return Ok(MutationResult::Skipped);
            }
            let mut rng = thread_rng();
            let selected = dist.unwrap().sample(&mut rng);
            let limit = input.part_limit(selected);
            let mutated = input.part_mut(selected).unwrap();
            state.set_max_size(limit);
            self.mutate(state, mutated)
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        M::post_exec(self, state, new_corpus_id)
    }
}

mod macros {
    /// Implements the marker trait [`super::DefaultMultipartMutator`] for one to many types, e.g.:
    ///
    /// ```rs
    /// impl_default_multipart!(
    ///     // --- havoc ---
    ///     BitFlipMutator,
    ///     ByteAddMutator,
    ///     ByteDecMutator,
    ///     ByteFlipMutator,
    ///     ByteIncMutator,
    ///     ...
    /// );
    /// ```
    #[macro_export]
    macro_rules! impl_default_multipart {
        ($mutator: ty, $($mutators: ty),+$(,)?) => {
            impl $crate::mutators::multi::DefaultMultipartMutator for $mutator {}
            impl_default_multipart!($($mutators),+);
        };

        ($mutator: ty) => {
            impl $crate::mutators::multi::DefaultMultipartMutator for $mutator {}
        };
    }
}

impl_default_multipart!(
    // --- havoc ---
    BitFlipMutator,
    ByteAddMutator,
    ByteDecMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteInterestingMutator,
    ByteNegMutator,
    ByteRandMutator,
    BytesCopyMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesInsertCopyMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesRandSetMutator,
    BytesSetMutator,
    BytesSwapMutator,
    // crossover has a custom implementation below
    DwordAddMutator,
    DwordInterestingMutator,
    QwordAddMutator,
    WordAddMutator,
    WordInterestingMutator,
    // --- token ---
    TokenInsert,
    TokenReplace,
    // ---  i2s  ---
    I2SRandReplace,
);

impl<I, S> Mutator<MultipartInput<I>, S> for CrossoverInsertMutator<I>
where
    S: HasCorpus<Input = MultipartInput<I>> + HasMaxSize + HasRand,
    I: Input + HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I>,
    ) -> Result<MutationResult, Error> {
        if input.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // return Ok(MutationResult::Skipped);
        // we can eat the slight bias; number of parts will be small
        let name_choice = state.rand_mut().next() as usize;
        let part_choice = state.rand_mut().next() as usize;

        // We special-case crossover with self
        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                let choice = name_choice % input.names().len();
                let name = input.names()[choice].clone();
                let limit = input.part_limit(choice);
                let other_size = input.parts()[choice].bytes().len();
                if other_size < 2 {
                    return Ok(MutationResult::Skipped);
                }

                let parts = input.parts_by_name(&name).count() - 1;

                if parts == 0 {
                    return Ok(MutationResult::Skipped);
                }

                let maybe_size = input
                    .parts_by_name(&name)
                    .filter(|&(p, _)| p != choice)
                    .nth(part_choice % parts)
                    .map(|(id, part)| (id, part.bytes().len()));

                if let Some((part_idx, size)) = maybe_size {
                    if size >= limit {
                        return Ok(MutationResult::Skipped);
                    }
                    let target = state.rand_mut().below(size);
                    let range = rand_range(state, other_size, limit - size);

                    let [part, chosen] = match part_idx.cmp(&choice) {
                        Ordering::Less => input.parts_mut([part_idx, choice]),
                        Ordering::Equal => {
                            unreachable!("choice should never equal the part idx!")
                        }
                        Ordering::Greater => {
                            let [chosen, part] = input.parts_mut([choice, part_idx]);
                            [part, chosen]
                        }
                    };

                    return Ok(Self::crossover_insert(part, size, target, range, chosen));
                }

                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get(id)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;
        if other.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let choice = name_choice % other.names().len();
        let name = &other.names()[choice];
        let limit = other.part_limit(choice);
        let weight = other.part_weight(choice);
        let other_size = other.parts()[choice].bytes().len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let parts = input.parts_by_name(name).count();

        if parts > 0 {
            let (_, part) = input
                .parts_by_name_mut(name)
                .nth(part_choice % parts)
                .unwrap();
            drop(other_testcase);
            let size = part.bytes().len();
            if size >= limit {
                return Ok(MutationResult::Skipped);
            }
            let target = state.rand_mut().below(size);
            let range = rand_range(state, other_size, limit - size - 1);

            let other_testcase = state.corpus().get(id)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();

            Ok(Self::crossover_insert(
                part,
                size,
                target,
                range,
                &other.parts()[choice],
            ))
        } else {
            // just add it!
            input.add_part(name.clone(), other.parts()[choice].clone(), limit, weight);

            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, S> Mutator<MultipartInput<I>, S> for CrossoverReplaceMutator<I>
where
    S: HasCorpus<Input = MultipartInput<I>> + HasMaxSize + HasRand,
    I: Input + HasMutatorBytes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I>,
    ) -> Result<MutationResult, Error> {
        if input.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // we can eat the slight bias; number of parts will be small
        let name_choice = state.rand_mut().next() as usize;
        let part_choice = state.rand_mut().next() as usize;

        // We special-case crossover with self
        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                let choice = name_choice % input.names().len();
                let name = input.names()[choice].clone();

                let other_size = input.parts()[choice].bytes().len();
                if other_size < 2 {
                    return Ok(MutationResult::Skipped);
                }

                let parts = input.parts_by_name(&name).count() - 1;

                if parts == 0 {
                    return Ok(MutationResult::Skipped);
                }

                let maybe_size = input
                    .parts_by_name(&name)
                    .filter(|&(p, _)| p != choice)
                    .nth(part_choice % parts)
                    .map(|(id, part)| (id, part.bytes().len()));

                if let Some((part_idx, size)) = maybe_size {
                    let target = state.rand_mut().below(size);
                    let range = rand_range(state, other_size, min(other_size, size - target));

                    let [part, chosen] = match part_idx.cmp(&choice) {
                        Ordering::Less => input.parts_mut([part_idx, choice]),
                        Ordering::Equal => {
                            unreachable!("choice should never equal the part idx!")
                        }
                        Ordering::Greater => {
                            let [chosen, part] = input.parts_mut([choice, part_idx]);
                            [part, chosen]
                        }
                    };

                    return Ok(Self::crossover_replace(part, target, range, chosen));
                }

                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get(id)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;
        if other.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let choice = name_choice % other.names().len();
        let name = &other.names()[choice];

        let other_size = other.parts()[choice].bytes().len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let parts = input.parts_by_name(name).count();

        if parts > 0 {
            let (_, part) = input
                .parts_by_name_mut(name)
                .nth(part_choice % parts)
                .unwrap();
            drop(other_testcase);
            let size = part.bytes().len();

            let target = state.rand_mut().below(size);
            let range = rand_range(state, other_size, min(other_size, size - target));

            let other_testcase = state.corpus().get(id)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();
            part.bytes_mut()[0] = part.bytes_mut()[0];
            Ok(Self::crossover_replace(
                part,
                target,
                range,
                &other.parts()[choice],
            ))
        } else {
            // just add it!
            input.add_part(name.clone(), other.parts()[choice].clone(), other.part_limit(choice), other.part_weight(choice));

            Ok(MutationResult::Mutated)
        }
    }
}
