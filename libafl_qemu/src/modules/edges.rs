use std::{cell::UnsafeCell, cmp::max};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, HasMetadata};
use libafl_qemu_sys::GuestAddr;
use crate::{qemu::HookId, BlockHookId};
#[cfg(emulation_mode = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;
pub use libafl_targets::{
    edges_map_mut_ptr, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE_IN_USE, EDGES_MAP_SIZE_MAX,
    MAX_EDGES_FOUND,
};
use serde::{Deserialize, Serialize};

#[cfg(emulation_mode = "systemmode")]
use crate::modules::QemuInstrumentationPagingFilter;
use crate::{
    emu::EmulatorModules,
    modules::{
        hash_me, EmulatorModule, EmulatorModuleTuple, HasInstrumentationFilter, IsFilter,
        QemuInstrumentationAddressRangeFilter,
    },
    qemu::Hook, EdgeHookId,
};

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(GuestAddr, GuestAddr), u64>,
    pub current_id: u64,
}

impl QemuEdgesMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

libafl_bolts::impl_serdeany!(QemuEdgesMapMetadata);

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct EdgeCoverageModule {
    address_filter: QemuInstrumentationAddressRangeFilter,
    use_hitcounts: bool,
    hook_id : Option<EdgeHookId>,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct EdgeCoverageModule {
    address_filter: QemuInstrumentationAddressRangeFilter,
    paging_filter: QemuInstrumentationPagingFilter,
    use_hitcounts: bool,
    hook_id : Option<EdgeHookId>,
}

#[cfg(emulation_mode = "usermode")]
impl EdgeCoverageModule {
    #[must_use]
    pub fn new(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl EdgeCoverageModule {
    #[must_use]
    pub fn new(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: true,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: false,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, paging_id: Option<GuestPhysAddr>) -> bool {
        self.address_filter.allowed(addr) && self.paging_filter.allowed(paging_id)
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for EdgeCoverageModule {
    fn default() -> Self {
        Self::new(QemuInstrumentationAddressRangeFilter::None)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for EdgeCoverageModule {
    fn default() -> Self {
        Self::new(
            QemuInstrumentationAddressRangeFilter::None,
            QemuInstrumentationPagingFilter::None,
        )
    }
}

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for EdgeCoverageModule {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.address_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.address_filter
    }
}

#[cfg(emulation_mode = "systemmode")]
impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for EdgeCoverageModule {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &self.paging_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        &mut self.paging_filter
    }
}

impl<S> EmulatorModule<S> for EdgeCoverageModule
where
    S: Unpin + UsesInput + HasMetadata,
{
    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
        where
            ET: EmulatorModuleTuple<S>, {
        if let Some(hook_id) = self.hook_id {
            hook_id.remove(true);
        }
        if self.use_hitcounts {
            let hook_id = emulator_modules.edges(
                Hook::Function(gen_unique_edge_ids::<ET, S>),
                Hook::Function(trace_edge_hitcount::<ET, S>),
            );
            // let hook_id =
            //     emulator_modules.edges(Hook::Function(gen_unique_edge_ids::<ET, S>), Hook::Empty);
            // unsafe {
            //     libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
            //         hook_id.0,
            //         Some(libafl_qemu_sys::libafl_jit_trace_edge_hitcount),
            //     );
            // }
            self.hook_id = Some(hook_id);
        } else {
            let hook_id = emulator_modules.edges(
                Hook::Function(gen_unique_edge_ids::<ET, S>),
                Hook::Function(trace_edge_single::<ET, S>),
            );
            // let hook_id =
            //     emulator_modules.edges(Hook::Function(gen_unique_edge_ids::<ET, S>), Hook::Empty);
            // unsafe {
            //     libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
            //         hook_id.0,
            //         Some(libafl_qemu_sys::libafl_jit_trace_edge_single),
            //     );
            // }
            self.hook_id = Some(hook_id);
        }
    }
    fn pre_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, _input: &<S as UsesInput>::Input)
        where
            ET: EmulatorModuleTuple<S>, 
    {
    }

    fn post_exec<OT, ET>(
            &mut self,
            _emulator_modules: &mut EmulatorModules<ET, S>,
            _input: &<S as UsesInput>::Input,
            _observers: &mut OT,
            _exit_kind: &mut libafl::prelude::ExitKind,
        ) where
            OT: libafl::prelude::ObserversTuple<S>,
            ET: EmulatorModuleTuple<S>, 
    {
        // self.hook_id.unwrap().remove(false);
    }
    // fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    // where
    //     ET: EmulatorModuleTuple<S>,
    // {
        
    // }
}

pub type CollidingEdgeCoverageModule = EdgeCoverageChildModule;

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct EdgeCoverageChildModule {
    address_filter: QemuInstrumentationAddressRangeFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct EdgeCoverageChildModule {
    address_filter: QemuInstrumentationAddressRangeFilter,
    paging_filter: QemuInstrumentationPagingFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "usermode")]
impl EdgeCoverageChildModule {
    #[must_use]
    pub fn new(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl EdgeCoverageChildModule {
    #[must_use]
    pub fn new(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, paging_id: Option<GuestPhysAddr>) -> bool {
        self.address_filter.allowed(addr) && self.paging_filter.allowed(paging_id)
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for EdgeCoverageChildModule {
    fn default() -> Self {
        Self::new(QemuInstrumentationAddressRangeFilter::None)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for EdgeCoverageChildModule {
    fn default() -> Self {
        Self::new(
            QemuInstrumentationAddressRangeFilter::None,
            QemuInstrumentationPagingFilter::None,
        )
    }
}

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for EdgeCoverageChildModule {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.address_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.address_filter
    }
}

#[cfg(emulation_mode = "systemmode")]
impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for EdgeCoverageChildModule {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &self.paging_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        &mut self.paging_filter
    }
}

impl<S> EmulatorModule<S> for EdgeCoverageChildModule
where
    S: Unpin + UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        if self.use_hitcounts {
            emulator_modules.edges(
                Hook::Function(gen_hashed_edge_ids::<ET, S>),
                Hook::Raw(trace_edge_hitcount_ptr),
            );
        } else {
            emulator_modules.edges(
                Hook::Function(gen_hashed_edge_ids::<ET, S>),
                Hook::Raw(trace_edge_single_ptr),
            );
        }
    }
}

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct EdgeCoverageClassicModule {
    address_filter: QemuInstrumentationAddressRangeFilter,
    use_hitcounts: bool,
    use_jit: bool,
    hook_id : Option<BlockHookId>,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct EdgeCoverageClassicModule {
    address_filter: QemuInstrumentationAddressRangeFilter,
    paging_filter: QemuInstrumentationPagingFilter,
    use_hitcounts: bool,
    use_jit: bool,
    hook_id : Option<BlockHookId>,
}

#[cfg(emulation_mode = "usermode")]
impl EdgeCoverageClassicModule {
    #[must_use]
    pub fn new(address_filter: QemuInstrumentationAddressRangeFilter, use_jit: bool) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
            use_jit,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: QemuInstrumentationAddressRangeFilter,
        use_jit: bool,
    ) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
            use_jit,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl EdgeCoverageClassicModule {
    #[must_use]
    pub fn new(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
        use_jit: bool,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: true,
            use_jit,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
        use_jit: bool,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: false,
            use_jit,
            hook_id : None,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, paging_id: Option<GuestPhysAddr>) -> bool {
        self.address_filter.allowed(addr) && self.paging_filter.allowed(paging_id)
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for EdgeCoverageClassicModule {
    fn default() -> Self {
        Self::new(QemuInstrumentationAddressRangeFilter::None, false)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for EdgeCoverageClassicModule {
    fn default() -> Self {
        Self::new(
            QemuInstrumentationAddressRangeFilter::None,
            QemuInstrumentationPagingFilter::None,
            false,
        )
    }
}

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for EdgeCoverageClassicModule {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.address_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.address_filter
    }
}

#[cfg(emulation_mode = "systemmode")]
impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for EdgeCoverageClassicModule {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &self.paging_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        &mut self.paging_filter
    }
}

#[allow(clippy::collapsible_else_if)]
impl<S> EmulatorModule<S> for EdgeCoverageClassicModule
where
    S: Unpin + UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;
    fn pre_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, _input: &<S as UsesInput>::Input)
        where
            ET: EmulatorModuleTuple<S>, {
        let hook_id = emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<ET, S>),
            Hook::Empty,
            Hook::Raw(trace_block_transition_hitcount),
        );
        unsafe {
            PREV_LOC.with(|prev_loc| {
                *prev_loc.get() = 0;
            });
            MAX_EDGES_FOUND = EDGES_MAP_SIZE_IN_USE;
        }
        self.hook_id = Some(hook_id);
    }
    fn post_exec<OT, ET>(
            &mut self,
            _emulator_modules: &mut EmulatorModules<ET, S>,
            _input: &<S as UsesInput>::Input,
            _observers: &mut OT,
            _exit_kind: &mut libafl::prelude::ExitKind,
        ) where
            OT: libafl::prelude::ObserversTuple<S>,
            ET: EmulatorModuleTuple<S>, {
        self.hook_id.unwrap().remove(false);
        
    }
    // fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    // where
    //     ET: EmulatorModuleTuple<S>,
    // {
    //     if self.use_hitcounts {
    //         if self.use_jit {
    //             let hook_id = emulator_modules.blocks(
    //                 Hook::Function(gen_hashed_block_ids::<ET, S>),
    //                 Hook::Empty,
    //                 Hook::Empty,
    //             );

    //             unsafe {
    //                 libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
    //                     hook_id.0,
    //                     Some(libafl_qemu_sys::libafl_jit_trace_block_hitcount),
    //                 );
    //             }
    //         } else {
    //             emulator_modules.blocks(
    //                 Hook::Function(gen_hashed_block_ids::<ET, S>),
    //                 Hook::Empty,
    //                 Hook::Raw(trace_block_transition_hitcount),
    //             );
    //         }
    //     } else {
    //         if self.use_jit {
    //             let hook_id = emulator_modules.blocks(
    //                 Hook::Function(gen_hashed_block_ids::<ET, S>),
    //                 Hook::Empty,
    //                 Hook::Empty,
    //             );

    //             unsafe {
    //                 libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
    //                     hook_id.0,
    //                     Some(libafl_qemu_sys::libafl_jit_trace_block_single),
    //                 );
    //             }
    //         } else {
    //             emulator_modules.blocks(
    //                 Hook::Function(gen_hashed_block_ids::<ET, S>),
    //                 Hook::Empty,
    //                 Hook::Raw(trace_block_transition_single),
    //             );
    //         }
    //     }
    // }
}

thread_local!(static PREV_LOC : UnsafeCell<u64> = const { UnsafeCell::new(0) });

pub fn gen_unique_edge_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput + HasMetadata,
{
    if !emulator_modules.qemu().get_infuzz() {
        return None;
    }   
    if let Some(h) = emulator_modules.get::<EdgeCoverageModule>() {
        #[cfg(emulation_mode = "usermode")]
        {
            if !h.must_instrument(src) && !h.must_instrument(dest) {
                return None;
            }
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !h.must_instrument(src, paging_id) && !h.must_instrument(dest, paging_id) {
                return None;
            }
        }
    }
    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    let meta = state.metadata_or_insert_with(QemuEdgesMapMetadata::new);

    match meta.map.entry((src, dest)) {
        Entry::Occupied(e) => {
            let id = *e.get();
            let nxt = (id as usize + 1) & (EDGES_MAP_SIZE_MAX - 1);
            unsafe {
                MAX_EDGES_FOUND = max(MAX_EDGES_FOUND, nxt);
            }
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = (id + 1) & (EDGES_MAP_SIZE_MAX as u64 - 1);
            unsafe {
                MAX_EDGES_FOUND = meta.current_id as usize;
            }
            // GuestAddress is u32 for 32 bit guests
            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

fn trace_edge_hitcount<ET, S>(emulator_modules: &mut EmulatorModules<ET, S>, state: Option<&mut S>, id: u64) 
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput + HasMetadata, {
    if !emulator_modules.qemu().get_infuzz() {
        return;
    }
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
    }
}

fn trace_edge_single<ET, S>(emulator_modules: &mut EmulatorModules<ET, S>, state: Option<&mut S>, id: u64)
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput + HasMetadata, {
    if !emulator_modules.qemu().get_infuzz() {
        return;
    }
    unsafe {
        EDGES_MAP[id as usize] = 1;
    }
}

pub fn gen_hashed_edge_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageChildModule>() {
        #[cfg(emulation_mode = "usermode")]
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !h.must_instrument(src, paging_id) && !h.must_instrument(dest, paging_id) {
                return None;
            }
        }
    }
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some((hash_me(src as u64) ^ hash_me(dest as u64)) & (EDGES_MAP_SIZE_MAX as u64 - 1))
}

pub extern "C" fn trace_edge_hitcount_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = (*ptr).wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = 1;
    }
}

pub fn gen_hashed_block_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageClassicModule>() {
        #[cfg(emulation_mode = "usermode")]
        {
            if !h.must_instrument(pc) {
                return None;
            }
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !h.must_instrument(pc, paging_id) {
                return None;
            }
        }
    }
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(hash_me(pc as u64) & (EDGES_MAP_SIZE_IN_USE as u64 - 1))
}

pub extern "C" fn trace_block_transition_hitcount(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = (*prev_loc.get() ^ id) as usize;
            let ptr = EDGES_MAP_PTR.add(x as usize);
            *ptr = (*ptr).wrapping_add(1);
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

pub extern "C" fn trace_block_transition_single(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = (*prev_loc.get() ^ id) as usize;
            let ptr = EDGES_MAP_PTR.add(x as usize);
            *ptr = 1;
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}
