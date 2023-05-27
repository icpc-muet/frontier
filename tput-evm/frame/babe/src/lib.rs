// This file is part of Substrate.

// Copyright (C) 2019-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Consensus extension module for BABE consensus. Collects on-chain randomness
//! from VRF outputs and manages epoch transitions.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_must_use, unsafe_code, unused_variables, unused_must_use)]

use scale_codec::{ Decode, Encode, MaxEncodedLen };
use frame_support::{
	dispatch::{DispatchResultWithPostInfo, Pays, DispatchResult},
	ensure,
	traits::{
		ConstU32, DisabledValidators, FindAuthor, Get, KeyOwnerProofSystem, OnTimestampSet,
		OneSessionHandler, Randomness as RandomnessPoc, Currency, ReservableCurrency,
	},
	weights::Weight,
	BoundedVec, WeakBoundedVec,
};
use sp_application_crypto::ByteArray;
use sp_runtime::{
	generic::DigestItem,
	traits::{IsMember, One, SaturatedConversion, Saturating, Zero},
	RuntimeAppPublic,
	ConsensusEngineId, KeyTypeId, Permill,
	offchain::{
		storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
	},
	transaction_validity::{
		InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
};

use frame_system::{
	self as system,
	offchain::{
		AppCrypto, CreateSignedTransaction,
		SignedPayload, SigningTypes, SubmitTransaction,
	},
};

use sp_session::{GetSessionNumber, GetValidatorCount};
use sp_std::prelude::*;

use sp_consensus_babe::{
	digests::{NextConfigDescriptor, NextEpochDescriptor, PreDigest},
	AllowedSlots, BabeAuthorityWeight, BabeEpochConfiguration, ConsensusLog, Epoch,
	EquivocationProof, Slot, BABE_ENGINE_ID,
};
use sp_consensus_vrf::schnorrkel;

use pallet_staking::{self as staking};

pub use sp_consensus_babe::{AuthorityId, PUBLIC_KEY_LENGTH, RANDOMNESS_LENGTH, VRF_OUTPUT_LENGTH};

const LOG_TARGET: &str = "runtime::babe";

mod default_weights;
mod equivocation;
mod randomness;

#[cfg(any(feature = "runtime-benchmarks", test))]
mod benchmarking;
#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

pub use equivocation::{BabeEquivocationOffence, EquivocationHandler, HandleEquivocation};
#[allow(deprecated)]
pub use randomness::CurrentBlockRandomness;
pub use randomness::{
	ParentBlockRandomness, RandomnessFromOneEpochAgo, RandomnessFromTwoEpochsAgo,
};

pub use pallet::*;

pub trait WeightInfo {
	fn plan_config_change() -> Weight;
	fn report_equivocation(validator_count: u32) -> Weight;
}

/// Trigger an epoch change, if any should take place.
pub trait EpochChangeTrigger {
	/// Trigger an epoch change, if any should take place. This should be called
	/// during every block, after initialization is done.
	fn trigger<T: Config>(now: T::BlockNumber);
}

/// A type signifying to BABE that an external trigger
/// for epoch changes (e.g. pallet-session) is used.
pub struct ExternalTrigger;

impl EpochChangeTrigger for ExternalTrigger {
	fn trigger<T: Config>(_: T::BlockNumber) {} // nothing - trigger is external.
}

/// A type signifying to BABE that it should perform epoch changes
/// with an internal trigger, recycling the same authorities forever.
pub struct SameAuthoritiesForever;

impl EpochChangeTrigger for SameAuthoritiesForever {
	fn trigger<T: Config>(now: T::BlockNumber) {
		if <Pallet<T>>::should_epoch_change(now) {
			let authorities = <Pallet<T>>::authorities();
			let next_authorities = authorities.clone();

			<Pallet<T>>::enact_epoch_change(authorities, next_authorities);
		}
	}
}

const UNDER_CONSTRUCTION_SEGMENT_LENGTH: u32 = 256;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// The BABE Pallet
	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	#[pallet::disable_frame_system_supertrait_check]
	pub trait Config: CreateSignedTransaction<Call<Self>> + pallet_timestamp::Config + staking::Config + frame_system::Config {
		/// The amount of time, in slots, that each epoch should last.
		/// NOTE: Currently it is not possible to change the epoch duration after
		/// the chain has started. Attempting to do so will brick block production.
		#[pallet::constant]
		type EpochDuration: Get<u64>;

		/// The expected average block time at which BABE should be creating
		/// blocks. Since BABE is probabilistic it is not trivial to figure out
		/// what the expected average block time should be based on the slot
		/// duration and the security parameter `c` (where `1 - c` represents
		/// the probability of a slot being empty).
		#[pallet::constant]
		type ExpectedBlockTime: Get<Self::Moment>;

		/// BABE requires some logic to be triggered on every block to query for whether an epoch
		/// has ended and to perform the transition to the next epoch.
		///
		/// Typically, the `ExternalTrigger` type should be used. An internal trigger should only be
		/// used when no other module is responsible for changing authority set.
		type EpochChangeTrigger: EpochChangeTrigger;

		/// A way to check whether a given validator is disabled and should not be authoring blocks.
		/// Blocks authored by a disabled validator will lead to a panic as part of this module's
		/// initialization.
		type DisabledValidators: DisabledValidators;

		/// The proof of key ownership, used for validating equivocation reports.
		/// The proof must include the session index and validator count of the
		/// session at which the equivocation occurred.
		type KeyOwnerProof: Parameter + GetSessionNumber + GetValidatorCount;

		/// The identification of a key owner, used when reporting equivocations.
		type KeyOwnerIdentification: Parameter;

		/// A system for proving ownership of keys, i.e. that a given key was part
		/// of a validator set, needed for validating equivocation reports.
		type KeyOwnerProofSystem: KeyOwnerProofSystem<
			(KeyTypeId, AuthorityId),
			Proof = Self::KeyOwnerProof,
			IdentificationTuple = Self::KeyOwnerIdentification,
		>;

		/// The equivocation handling subsystem, defines methods to report an
		/// offence (after the equivocation has been validated) and for submitting a
		/// transaction to report an equivocation (from an offchain context).
		/// NOTE: when enabling equivocation handling (i.e. this type isn't set to
		/// `()`) you must use this pallet's `ValidateUnsigned` in the runtime
		/// definition.
		type HandleEquivocation: HandleEquivocation<Self>;

		type WeightInfo: WeightInfo;

		/// Max number of authorities allowed
		#[pallet::constant]
		type MaxAuthorities: Get<u32>;

		//** w3v poc changes start */
		type AuthorityId: Member
			+ Parameter
			+ RuntimeAppPublic
			+ MaybeSerializeDeserialize
			+ MaxEncodedLen
			+ Ord;
		
		type MaxBlocks: Get<u32>;

		type TotalBlocks: Get<u32>;
	
		#[pallet::constant]
		type GracePeriod: Get<Self::BlockNumber>;
	
		#[pallet::constant]
		type UnsignedInterval: Get<u64>;
	
		#[pallet::constant]
		type UnsignedPriority: Get<TransactionPriority>;
	
		#[pallet::constant]
		type EipInterval: Get<u64>;

		type PocRandomness: RandomnessPoc<Self::Hash, Self::BlockNumber>;

		/// Currency type for this pallet.
		type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;
		//** w3v poc changes end */
	}

	#[pallet::error]
	pub enum Error<T> {
		/// An equivocation proof provided as part of an equivocation report is invalid.
		InvalidEquivocationProof,
		/// A key ownership proof provided as part of an equivocation report is invalid.
		InvalidKeyOwnershipProof,
		/// A given equivocation report is valid but already previously reported.
		DuplicateOffenceReport,
		/// Submitted configuration is invalid.
		InvalidConfiguration,
	}

	/// Current epoch index.
	#[pallet::storage]
	#[pallet::getter(fn epoch_index)]
	pub type EpochIndex<T> = StorageValue<_, u64, ValueQuery>;

	/// Current epoch authorities.
	#[pallet::storage]
	#[pallet::getter(fn authorities)]
	pub type Authorities<T: Config> = StorageValue<
		_,
		WeakBoundedVec<(AuthorityId, BabeAuthorityWeight), T::MaxAuthorities>,
		ValueQuery,
	>;

	//** w3v poc changes start */
	#[pallet::storage]
	pub(super) type EIP<T: Config> = StorageMap<_, Blake2_128Concat, (u32, u32), u32, ValueQuery>;

	#[pallet::storage]
	pub(super) type EIPCount<T: Config> = StorageMap<_, Blake2_128Concat, u32, u32, ValueQuery>;

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Nextunsigned at is used to call the unsigned transaction at a particular block
	#[pallet::storage]
	#[pallet::getter(fn next_unsigned_at)]
	pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, Slot, ValueQuery>;

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Get the total current blocks
	// #[pallet::storage]
	// #[pallet::getter(fn get_current_total_blocks)]
	// pub(super) type CurrentTotalBlocks<T: Config> = StorageValue<_, (u32, u32), ValueQuery>;

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Get the nonce for the random number generation
	#[pallet::storage]
	#[pallet::getter(fn get_nonce)]
	pub(super) type Nonce<T: Config> = StorageValue<_, u32, ValueQuery>;
	
	/// W3v PoC Changes, Author: Zubair Buriro
	/// Implementation of PoC Consensus Algorithm
	/// This storage is added to store the custom schedule for the consensus
	/// The schedule is a map of round and authorities for that round
	/// todo: The schedule is updated by the root account
	#[pallet::storage]
	#[pallet::getter(fn get_next_schedule)]
	// add storage map with key as round and value as vector of authorities
	pub(super) type NextSchedule<T: Config> = StorageMap<_, Blake2_128Concat, u32, BoundedVec<u32, T::MaxBlocks>, ValueQuery>;


	#[pallet::storage]
	#[pallet::getter(fn get_current_schedule)]
	// add storage with vector of authorities
	pub(super) type CurrentSchedule<T: Config> = StorageValue<_, BoundedVec<u32, T::MaxBlocks>, ValueQuery>;


	// Current round for the custom consensus.
	#[pallet::storage]
	#[pallet::getter(fn current_round)]
	pub(super) type CurrentRound<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// The current top round for the custom consensus.
	#[pallet::storage]
	#[pallet::getter(fn top_round)]
	pub(super) type TopRound<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// The current block index for custom consensus.
	#[pallet::storage]
	#[pallet::getter(fn current_round_index)]
	pub(super) type CurrentRoundIdx<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// Current epoch poc authorities.
	#[pallet::storage]
	#[pallet::getter(fn poc_authorities)]
	pub type PocAuthorities<T: Config> = StorageValue<
		_,
		BoundedVec<T::AuthorityId, T::MaxAuthorities>,
		ValueQuery,
	>;

	// ** w3v poc changes end */

	/// The slot at which the first epoch actually started. This is 0
	/// until the first block of the chain.
	#[pallet::storage]
	#[pallet::getter(fn genesis_slot)]
	pub type GenesisSlot<T> = StorageValue<_, Slot, ValueQuery>;

	/// Current slot number.
	#[pallet::storage]
	#[pallet::getter(fn current_slot)]
	pub type CurrentSlot<T> = StorageValue<_, Slot, ValueQuery>;

	/// The epoch randomness for the *current* epoch.
	///
	/// # Security
	///
	/// This MUST NOT be used for gambling, as it can be influenced by a
	/// malicious validator in the short term. It MAY be used in many
	/// cryptographic protocols, however, so long as one remembers that this
	/// (like everything else on-chain) it is public. For example, it can be
	/// used where a number is needed that cannot have been chosen by an
	/// adversary, for purposes such as public-coin zero-knowledge proofs.
	// NOTE: the following fields don't use the constants to define the
	// array size because the metadata API currently doesn't resolve the
	// variable to its underlying value.
	#[pallet::storage]
	#[pallet::getter(fn randomness)]
	pub type Randomness<T> = StorageValue<_, schnorrkel::Randomness, ValueQuery>;

	/// Pending epoch configuration change that will be applied when the next epoch is enacted.
	#[pallet::storage]
	pub(super) type PendingEpochConfigChange<T> = StorageValue<_, NextConfigDescriptor>;

	/// Next epoch randomness.
	#[pallet::storage]
	pub(super) type NextRandomness<T> = StorageValue<_, schnorrkel::Randomness, ValueQuery>;

	/// Next epoch authorities.
	#[pallet::storage]
	pub(super) type NextAuthorities<T: Config> = StorageValue<
		_,
		WeakBoundedVec<(AuthorityId, BabeAuthorityWeight), T::MaxAuthorities>,
		ValueQuery,
	>;

	/// Randomness under construction.
	///
	/// We make a trade-off between storage accesses and list length.
	/// We store the under-construction randomness in segments of up to
	/// `UNDER_CONSTRUCTION_SEGMENT_LENGTH`.
	///
	/// Once a segment reaches this length, we begin the next one.
	/// We reset all segments and return to `0` at the beginning of every
	/// epoch.
	#[pallet::storage]
	pub(super) type SegmentIndex<T> = StorageValue<_, u32, ValueQuery>;

	/// TWOX-NOTE: `SegmentIndex` is an increasing integer, so this is okay.
	#[pallet::storage]
	pub(super) type UnderConstruction<T: Config> = StorageMap<
		_,
		Twox64Concat,
		u32,
		BoundedVec<schnorrkel::Randomness, ConstU32<UNDER_CONSTRUCTION_SEGMENT_LENGTH>>,
		ValueQuery,
	>;

	/// Temporary value (cleared at block finalization) which is `Some`
	/// if per-block initialization has already been called for current block.
	#[pallet::storage]
	#[pallet::getter(fn initialized)]
	pub(super) type Initialized<T> = StorageValue<_, Option<PreDigest>>;

	/// This field should always be populated during block processing unless
	/// secondary plain slots are enabled (which don't contain a VRF output).
	///
	/// It is set in `on_finalize`, before it will contain the value from the last block.
	#[pallet::storage]
	#[pallet::getter(fn author_vrf_randomness)]
	pub(super) type AuthorVrfRandomness<T> =
		StorageValue<_, Option<schnorrkel::Randomness>, ValueQuery>;

	/// The block numbers when the last and current epoch have started, respectively `N-1` and
	/// `N`.
	/// NOTE: We track this is in order to annotate the block number when a given pool of
	/// entropy was fixed (i.e. it was known to chain observers). Since epochs are defined in
	/// slots, which may be skipped, the block numbers may not line up with the slot numbers.
	#[pallet::storage]
	pub(super) type EpochStart<T: Config> =
		StorageValue<_, (T::BlockNumber, T::BlockNumber), ValueQuery>;

	/// How late the current block is compared to its parent.
	///
	/// This entry is populated as part of block execution and is cleaned up
	/// on block finalization. Querying this storage entry outside of block
	/// execution context should always yield zero.
	#[pallet::storage]
	#[pallet::getter(fn lateness)]
	pub(super) type Lateness<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	/// The configuration for the current epoch. Should never be `None` as it is initialized in
	/// genesis.
	#[pallet::storage]
	#[pallet::getter(fn epoch_config)]
	pub(super) type EpochConfig<T> = StorageValue<_, BabeEpochConfiguration>;

	/// The configuration for the next epoch, `None` if the config will not change
	/// (you can fallback to `EpochConfig` instead in that case).
	#[pallet::storage]
	pub(super) type NextEpochConfig<T> = StorageValue<_, BabeEpochConfiguration>;

	#[cfg_attr(feature = "std", derive(Default))]
	#[pallet::genesis_config]
	pub struct GenesisConfig {
		pub authorities: Vec<(AuthorityId, BabeAuthorityWeight)>,
		pub epoch_config: Option<BabeEpochConfiguration>,
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig {
		fn build(&self) {
			SegmentIndex::<T>::put(0);
			Pallet::<T>::initialize_genesis_authorities(&self.authorities);
			EpochConfig::<T>::put(
				self.epoch_config.clone().expect("epoch_config must not be None"),
			);
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Initialization
		fn on_initialize(now: BlockNumberFor<T>) -> Weight {
			Self::initialize(now);

			if let Some(pre_digest) = Initialized::<T>::take().flatten() {
				
				// ** changes from aura */
				let new_slot = pre_digest.slot();
				// let current_slot = CurrentSlot::<T>::get();
				let mut current_index = CurrentRoundIdx::<T>::get();	
				let genesis_slot = <GenesisSlot<T>>::get();	
				let mut authorities = Self::get_current_schedule();
				let n_blocks: u32 = authorities.len() as u32;
				// get lateness and convert it into Slot

				let lateness: u64 = Self::lateness().try_into().unwrap_or(0);
				let diff: Slot = lateness.into();
				// let mut diff: Slot = 0.into();

				// convert block number to slot
				//let slot: Slot = lateness.into();

				// this is the first block of the chain, therefore set the next_unsigned at this block
				if *new_slot == *genesis_slot {
					
					<NextUnsignedAt<T>>::put(new_slot);
					
				} else {
					//let diff = new_slot.saturating_sub(current_slot);
					current_index = current_index.wrapping_add(*diff as u32 + 1);
					CurrentRoundIdx::<T>::put(current_index);
				}

				// get epochindex 
				let epoch_index = Self::epoch_index();


				log::info!(target: "w3v", "Current slot {:?}, lateness {:?}, current index: {:?},  EpochIndex: {:?}", new_slot,  lateness, current_index, epoch_index);

				// let mut idx = current_index % n_blocks;
				
				if current_index > 0u32 && current_index >= n_blocks {
					let new_round = Self::estimate_next_round();
					let current_index = current_index.wrapping_sub(n_blocks);
					if new_round > 0 {
						// current_index = (*diff as u32).wrapping_sub(1);
						CurrentRound::<T>::put(new_round);
						CurrentRoundIdx::<T>::put(current_index); // reset authority to 0
						authorities = Self::get_authorities_by_round(new_round);				
						// idx = current_index % (authorities.len() as u32);
						// set the new schedule as current schedule
						CurrentSchedule::<T>::put(authorities.clone());
						let list_authorities: Vec<u32> = authorities.clone().try_into().unwrap();
						log::info!(target: "w3v", "New round: {:?}, new authorities: {:?}", new_round, list_authorities.clone());
						Self::print_authorities(list_authorities.clone(), new_round);
						// rest nextunsigned transaction to 80 slots
						<NextUnsignedAt<T>>::put(new_slot + T::UnsignedInterval::get());
					} else {
						CurrentRoundIdx::<T>::put(current_index);
						log::info!(target: "w3v", "Current round reset, since new round was not found");
						
						if Self::current_round() == 0u32 {
							// rest nextunsigned transaction to current slot, because it is round 0
							<NextUnsignedAt<T>>::put(new_slot);

						} else {
							// rest nextunsigned transaction to 80 slots
							<NextUnsignedAt<T>>::put(new_slot + T::UnsignedInterval::get());
						}
						
					}
					
					log::info!(target: "w3v", "Next unsigned transaction set to {:?}", <NextUnsignedAt<T>>::get());

					// reset eip and eipcount
					// <EIP<T>>::remove(current_round);
					// <EIPCount<T>>::clear();

				}
			}

				// ** end aura changes */


			Weight::zero()
		}

		/// Block finalization
		fn on_finalize(_now: BlockNumberFor<T>) {
			// at the end of the block, we can safely include the new VRF output
			// from this block into the under-construction randomness. If we've determined
			// that this block was the first in a new epoch, the changeover logic has
			// already occurred at this point, so the under-construction randomness
			// will only contain outputs from the right epoch.
			if let Some(pre_digest) = Initialized::<T>::take().flatten() {
				let authority_index = pre_digest.authority_index();

				if T::DisabledValidators::is_disabled(authority_index) {
					panic!(
						"Validator with index {:?} is disabled and should not be attempting to author blocks.",
						authority_index,
					);
				}

				if let Some((vrf_output, vrf_proof)) = pre_digest.vrf() {
					let randomness: Option<schnorrkel::Randomness> = Authorities::<T>::get()
						.get(authority_index as usize)
						.and_then(|(authority, _)| {
							schnorrkel::PublicKey::from_bytes(authority.as_slice()).ok()
						})
						.and_then(|pubkey| {
							let current_slot = CurrentSlot::<T>::get();

							let transcript = sp_consensus_babe::make_transcript(
								&Self::randomness(),
								current_slot,
								EpochIndex::<T>::get(),
							);

							// NOTE: this is verified by the client when importing the block, before
							// execution. we don't run the verification again here to avoid slowing
							// down the runtime.
							debug_assert!(pubkey
								.vrf_verify(transcript.clone(), vrf_output, vrf_proof)
								.is_ok());

							vrf_output.0.attach_input_hash(&pubkey, transcript).ok()
						})
						.map(|inout| inout.make_bytes(sp_consensus_babe::BABE_VRF_INOUT_CONTEXT));

					if let Some(randomness) = pre_digest.is_primary().then(|| randomness).flatten()
					{
						Self::deposit_randomness(&randomness);
					}

					AuthorVrfRandomness::<T>::put(randomness);
				}
			}

			// remove temporary "environment" entry from storage
			Lateness::<T>::kill();
		}

		/// W3v PoC Changes, Author: Zubair Buriro
		/// Implementation of PoC Consensus Algorithm
		/// This function is modified to add the following functionality:
		/// 1. Get the current block number
		/// 2. Check if the block interval is complete
		/// 3. Get the block generation share
		/// 4. Initialize the current round of the schedule
		/// 5. Generate the dynamic schedule
		/// 6. Check if the schedule is complete
		/// 7. Submit the schedule back to the chain using unsigned transaction
		fn offchain_worker(block_number: T::BlockNumber) {
			
			
			if sp_io::offchain::is_validator() {
				// The entry point of your code called by offchain worker
				// get current round
				let current_round = Self::current_round();
				let current_slot = <CurrentSlot<T>>::get();
				let next_unsigned_at = <NextUnsignedAt<T>>::get();

				log::info!(target: "w3v", "Current round: {:?}, current slot: {:?}, next unsigned at: {:?}", current_round, current_slot, next_unsigned_at);	
				
				// wait for the next unsigned transaction interval
				if *next_unsigned_at > *current_slot {
					return;
				}
				
				
				// get current eip count
				let current_eip_count = EIPCount::<T>::get(current_round);
				let n_authorities = Authorities::<T>::decode_len().unwrap_or(0) as u32;

				// next eip after 80 + eip interval slots
				let next_eip_at = next_unsigned_at.saturating_add(T::EipInterval::get());
				
				log::info!(target: "w3v", "Current EIP count: {:?}, next EIP at: {:?} total authorities: {:?}", current_eip_count, next_eip_at, n_authorities);
				
				// get the local keys
				if (current_eip_count < n_authorities)  && (*current_slot <= *next_eip_at) {

					
					let (authority_index, key) = match Self::local_authority_keys().next() {
						Some((index, key)) => (index, key),
						None => return,
					};

					log::info!(target: "w3v", "Current authority index: {:?}, local key: {:?} inside local keys.", authority_index, key);
									

					// should send the transaction or not
					if Self::should_send_transaction(block_number, current_round, authority_index) {
						let eip = key.encode();
						let eip_hash = frame_support::Hashable::blake2_128(&eip);
						// hash the eip
						let rnd_no = Self::generate_random_seed(eip_hash.clone());
						let _result_eip_unsigned = Self::offchain_eip_unsigned_tx(current_slot, rnd_no, authority_index, current_round);

						// print result of should send transaction
						// log::info!(target: "w3v", "Should send transaction: {:?}", result_eip_unsigned);
						
						
					} else {
						// log::info!(target: "w3v", "Not sending transaction");
						return;
					}

					

				} else {
					// now create the schedule
					// check if the slot interval is complete
					// let next_unsigned_at = next_unsigned_at.saturating_add(T::EipInterval::get());
					if *current_slot < *next_eip_at {
						return;
					}

					let mut rnd_list = Vec::new();
					let mut seed: u32 = 0;

					for i in 0..n_authorities {
						let rnd = <EIP<T>>::get((current_round, i as u32));
						if rnd != 0 {
							rnd_list.push((i, rnd));
							log::info!(target: "w3v", "authority index: {:?}, random number: {:?}", i, rnd);
						}
					}

					if rnd_list.len() > 0 {
						// get the seed
						seed = rnd_list[0].1;	
						for i in 1..rnd_list.len() {
							seed = seed ^ rnd_list[i].1;
						}
					}

					log::info!(target: "w3v", "XOR value: {:?}", seed);

					// get block generation share
					let (bgs_share, b_max) = Self::get_block_generation_share(rnd_list.clone());

					if bgs_share.len() < 2 {
						log::info!(target: "w3v", "Not enough authorities to generate dynamic schedule");
						return;
					}

					loop {
						// initialize the current round of the schedule
						// let mut schedule = Vec::new();
						let schedule  =  Self::generate_dynamic_schedule(bgs_share.clone(), b_max, seed);	
						// check if schedule is complete
						if schedule.len() < b_max as usize {

							continue;

						} else {
							// add to schedule
							let data: BoundedVec<_, T::MaxBlocks> = schedule.try_into().unwrap();
							let result = Self::offchain_unsigned_tx(current_slot, data.clone());
							log::warn!("W3V POC: Offchain Worker: {:?}", result);
							if let Err(e) = result {
								log::error!("offchain_worker error: {:?}", e);
							} else {
								log::warn!("W3V POC: Schedule is complete, schedule length: {:?}, current max blocks: {:?}", data.len(), b_max);
							}
							break;
						}
					}
				}
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Report authority equivocation/misbehavior. This method will verify
		/// the equivocation proof and validate the given key ownership proof
		/// against the extracted offender. If both are valid, the offence will
		/// be reported.
		#[pallet::call_index(0)]
		#[pallet::weight(<T as Config>::WeightInfo::report_equivocation(
			key_owner_proof.validator_count(),
		))]
		pub fn report_equivocation(
			origin: OriginFor<T>,
			equivocation_proof: Box<EquivocationProof<T::Header>>,
			key_owner_proof: T::KeyOwnerProof,
		) -> DispatchResultWithPostInfo {
			let reporter = ensure_signed(origin)?;

			Self::do_report_equivocation(Some(reporter), *equivocation_proof, key_owner_proof)
		}

		/// Report authority equivocation/misbehavior. This method will verify
		/// the equivocation proof and validate the given key ownership proof
		/// against the extracted offender. If both are valid, the offence will
		/// be reported.
		/// This extrinsic must be called unsigned and it is expected that only
		/// block authors will call it (validated in `ValidateUnsigned`), as such
		/// if the block author is defined it will be defined as the equivocation
		/// reporter.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as Config>::WeightInfo::report_equivocation(
			key_owner_proof.validator_count(),
		))]
		pub fn report_equivocation_unsigned(
			origin: OriginFor<T>,
			equivocation_proof: Box<EquivocationProof<T::Header>>,
			key_owner_proof: T::KeyOwnerProof,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;

			Self::do_report_equivocation(
				T::HandleEquivocation::block_author(),
				*equivocation_proof,
				key_owner_proof,
			)
		}

		/// Plan an epoch config change. The epoch config change is recorded and will be enacted on
		/// the next call to `enact_epoch_change`. The config will be activated one epoch after.
		/// Multiple calls to this method will replace any existing planned config change that had
		/// not been enacted yet.
		#[pallet::call_index(2)]
		#[pallet::weight(<T as Config>::WeightInfo::plan_config_change())]
		pub fn plan_config_change(
			origin: OriginFor<T>,
			config: NextConfigDescriptor,
		) -> DispatchResult {
			ensure_root(origin)?;
			match config {
				NextConfigDescriptor::V1 { c, allowed_slots } => {
					ensure!(
						(c.0 != 0 || allowed_slots != AllowedSlots::PrimarySlots) && c.1 != 0,
						Error::<T>::InvalidConfiguration
					);
				},
			}
			PendingEpochConfigChange::<T>::put(config);
			Ok(())
		}

		/* w3v poc change start */
		#[pallet::weight(0)]
		#[pallet::call_index(3)]
		pub fn submit_schedule_unsigned(
				origin: OriginFor<T>,
				schedule: BoundedVec<u32, T::MaxBlocks>,
		) -> DispatchResultWithPostInfo {
				// This ensures that the function can only be called via unsigned transaction.
				let _ = ensure_none(origin)?;

				log::info!(target: "w3v", "W3V POC: Submit Schedule Unsigned: {:?}", schedule.len());

				// get top round
				let mut top_round = TopRound::<T>::get();
				top_round = top_round.saturating_add(1);
				
				// increment top round
				TopRound::<T>::put(top_round);
	
				// add schedule to storage
				NextSchedule::<T>::insert(top_round, schedule);
	
				// now increment the block number at which we expect next unsigned transaction.
				// let current_block = <system::Pallet<T>>::block_number();
				let current_slot = <CurrentSlot<T>>::get();
				<NextUnsignedAt<T>>::put(current_slot + T::UnsignedInterval::get());
				Ok(().into())
		}

	#[pallet::weight(0)]
	#[pallet::call_index(4)]
	pub fn submit_eip_unsigned(
			origin: OriginFor<T>,
			random_number: u32,
			authority_index: u32,
			round: u32,
	) -> DispatchResultWithPostInfo {
			
			
			// This ensures that the function can only be called via unsigned transaction.
			let _ = ensure_none(origin)?;



			// check if EIP count is less than authorities count
			// let n_authorities = <Authorities<T>>::decode_len().unwrap_or(0) as u32;

			// print the number of authorities and EIP count
			// log::info!(target: "w3v", "W3V POC: Number of authorities: {:?}, EIP count: {:?}", n_authorities, EIPCount::<T>::get(round));
			/*

			if EIPCount::<T>::get(round) >= n_authorities as u32 {
				log::warn!("W3V POC: All EIPs received.");
				return Ok(().into());
			}
			*/
			
			/*
			// check if the value exists in EIP
			if EIP::<T>::contains_key((round, authority_index)) {
				log::warn!("W3V POC: EIP already exists for round: {:?}, authority Index: {:?}", round, authority_index);
			} else {
				EIP::<T>::insert((round, authority_index), random_number);
				// increment the number of EIPs received
				let mut eip_count = EIPCount::<T>::get(round);
				eip_count = eip_count.saturating_add(1);
				EIPCount::<T>::insert(round, eip_count);
			}
			*/

			EIP::<T>::insert((round, authority_index), random_number);
				// increment the number of EIPs received
			let mut eip_count = EIPCount::<T>::get(round);
			eip_count = eip_count.saturating_add(1);
			EIPCount::<T>::insert(round, eip_count);

			Ok(().into())
	}

		/* w3v poc change end */
	}


	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;
		fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			Self::validate_unsigned(source, call)
		}

		fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
			Self::pre_dispatch(call)
		}
	}
}

/// A BABE public key
pub type BabeKey = [u8; PUBLIC_KEY_LENGTH];

impl<T: Config> FindAuthor<u32> for Pallet<T> {
	fn find_author<'a, I>(digests: I) -> Option<u32>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		for (id, mut data) in digests.into_iter() {
			if id == BABE_ENGINE_ID {
				let pre_digest: PreDigest = PreDigest::decode(&mut data).ok()?;
				return Some(pre_digest.authority_index())
			}
		}

		None
	}
}

impl<T: Config> IsMember<AuthorityId> for Pallet<T> {
	fn is_member(authority_id: &AuthorityId) -> bool {
		<Pallet<T>>::authorities().iter().any(|id| &id.0 == authority_id)
	}
}

impl<T: Config> pallet_session::ShouldEndSession<T::BlockNumber> for Pallet<T> {
	fn should_end_session(now: T::BlockNumber) -> bool {
		// it might be (and it is in current implementation) that session module is calling
		// `should_end_session` from it's own `on_initialize` handler, in which case it's
		// possible that babe's own `on_initialize` has not run yet, so let's ensure that we
		// have initialized the pallet and updated the current slot.
		Self::initialize(now);
		Self::should_epoch_change(now)
	}
}

impl<T: Config> Pallet<T> {


		// ** w3v poc changes start */
	/// W3v PoC Changes, Author: Zubair Buriro
	/// Implementation of PoC Consensus Algorithm
	/// Function to generate nonce for the random number generation
	fn get_and_increment_nonce() -> Vec<u8> {
		let nonce = Nonce::<T>::get();
		Nonce::<T>::put(nonce.wrapping_add(1));
		nonce.encode()
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Implementation of PoC Consensus Algorithm
	/// Function to get the local keys of the current node
	/// Verify the local keys with the authorities
	/// Return the local keys
	fn local_authority_keys() -> impl Iterator<Item = (u32, T::AuthorityId)> 
		where <T as pallet::Config>::AuthorityId: Ord
	{
		// authorities		
		let babe_authorities = Authorities::<T>::get();
			
		let mut authorities = Vec::new();

		for auth in babe_authorities.iter() {
			// log::info!("w3v: auth {:?}", auth);
			authorities.push(T::AuthorityId::decode(&mut auth.0.as_slice()).unwrap());
		}

		// local keystore
		// private & public keys of the node stored in local keystore
		let mut local_keys = T::AuthorityId::all();

		// log::info!("w3v: local keys {:?}", local_keys);

		local_keys.sort();
			
		authorities.into_iter().enumerate().filter_map(move |(index, authority)| {
			local_keys
				.binary_search(&authority)
				.ok()
				.map(|location| (index as u32, local_keys[location].clone()))
		})
		
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Generate static schedule
	/// This function is called once on initialization
	/// The following changes are done:
	/// 1. Generate the initial schedule for the round 0
	/// 2. Store the schedule in the storage
	/// 3. Log the schedule
	pub fn generate_static_schedule() -> DispatchResult {
		// On initilization, generate an static schedule
		let mut authorities: Vec<u32>= Vec::new();
		let n_authorities: usize = <Authorities<T>>::decode_len().unwrap_or(0);
		let count: u32 = 10;

		for i in 0..count as u32 {
			let idx = i % n_authorities as u32;
			authorities.push(idx);
		}

		let data: BoundedVec<_, T::MaxBlocks> = authorities.try_into().unwrap();
		
		CurrentSchedule::<T>::put(data.clone());
		NextSchedule::<T>::insert(0u32, data.clone());
		TopRound::<T>::put(0u32);
		CurrentRoundIdx::<T>::put(0u32);

		Ok(()) // return static schedule
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Helper function to get the share of invididual authority based on formula
	/// The following changes are done:
	/// 1. Get the block generation score of the authority
	/// 2. Get the sum of block generation score of all authority
	/// 3. Get the maximum number of blocks that can be generated in a round
	/// 4. Calculate the share of the authority
	/// 5. Return the share of the authority 
	fn block_generation_share(bgs: u64, sum_bgs: u64, b_max: u32) -> u32 {
		
		// convert into FixedU128 and then calculate
		//let bgs_fixed = FixedI128::from_rational(bgs as u128, 1);
		//let sum_bgs_fixed = FixedI128::from_rational(sum_bgs as u128, 1);
		//let b_max_fixed = FixedI128::from_u32(b_max);

		// Calculate the percentage as a FixedI128 value
		//let share_fixed = (bgs_fixed * b_max_fixed) / sum_bgs_fixed;

		//let share_ceil = share_fixed.ceil();

		// convert into u128 and then into u32
		// let share: f64 = share_ceil.into();
		/*
		let share = if share_ceil > FixedI128::from(18446744073709551615u64) {
			18446744073709551615u64
		} else {
			share_ceil.to_bits() as u64
		};

		*/
		// let share: u128 = TryInto::try_into(share_ceil).unwrap_or(0);

		//log::info!(target: "w3v", "share_fixed: {:?}, share_ceil: {:?}, share: {:?}", share_fixed, share_ceil, share);
		// let share = share_ceil.saturating_mul_ratio(1u128, 1u128).saturating_to_u64();

	
		let share: u64 = (bgs * b_max as u64) / sum_bgs; // todo round off to nearest integer

		share.try_into().unwrap()
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Count the block generation score the authority
	/// The following changes are done:
	/// 1. Get random number
	/// 2. Get security score
	/// 3. Get stack size
	/// 4. Calculate block generation score
	/// 5. Return block generation score
	fn block_generation_score(node_id: u32) -> u64 {
		// get random number
		let rand = Self::generate_random_number(0u32);
		let min_n: u32 = 50;
		let max_n: u32 = 100;
		let security_score: u64 = (rand % (max_n - min_n + 1) + min_n) as u64;
		let mut stack_size: u64 = 0;

		let authority_id = match Self::authorities().get(node_id as usize) {
			Some(author) => Some(author.0.clone()),
			None => None,
		};

		if authority_id.is_some() {
			let author = T::AccountId::decode(& mut authority_id.unwrap().as_slice()).unwrap();
			
			// get stack size from staking pallet
			stack_size = <staking::Pallet<T>>::ledger(&author).unwrap().total.saturated_into::<u64>();	
		}

		let mut bgs = security_score.saturating_add(stack_size); // block generation score

		// block generation score is 0 if security score is less than 50 or stack size is less than 900
		if security_score < 50 || stack_size < 250 {
			bgs = 0u64;
		}

		log::info!(target: "w3v", "Node Id: {:?}, Security score: {:?}, Stack size: {:?}, Block generation score: {:?}", node_id, security_score, stack_size, bgs);

		bgs // return block generation score
	}


	/// W3v PoC Changes, Author: Zubair Buriro
	/// Get the block generation share of all authorities
	/// The following changes are done:
	/// 1. Get the block generation score of all authorities
	/// 2. Get the sum of block generation score of all authorities
	/// 3. Get the block generation share of all authorities
	/// 4. Get the new block max
	/// 5. Return the block generation share of all authorities and new block max
	fn get_block_generation_share(rnd_list: Vec<(u32, u32)>) -> (Vec<(u32, u32)>, u32) {
		let mut bgs_all: Vec<u64> = Vec::new();
		let mut sum_bgs: u64 = 0;
		let b_max: u32 = <T::MaxBlocks>::get();
		let mut bgs_share: Vec<(u32, u32)> = Vec::new();
		let mut new_b_max: u32 = 0;

		// get authority set length
		let n_authorities = rnd_list.len();

		// get block generation score of all authorities
		for i in 0..n_authorities {
			let bgs: u64 = Self::block_generation_score(rnd_list[i].0);
			bgs_all.push(bgs);
			sum_bgs += bgs;
		}

		// log::info!(target: "w3v", "Block generation score of all authorities: {:?}", bgs_all.clone());

		// get block generation share of all authorities
		for i in 0..n_authorities {
			let share: u32 = Self::block_generation_share(bgs_all[i], sum_bgs, b_max);
			new_b_max += share;
			bgs_share.push((rnd_list[i].0, share));
		}

		log::info!(target: "w3v", "Block Max: {:?}, block generation share of all authorities: {:?}", new_b_max, bgs_share.clone());

		(bgs_share, new_b_max)  // return block generation share of all authorities
	}

	/// POC Changes, Author: Zubair Buriro
	/// Helper function to get total blocks in the current round
	pub fn get_total_blocks() -> u32 {
		// let (_round, mut total_blocks): (u32, u32) = <CurrentTotalBlocks<T>>::get();

		let mut total_blocks = <CurrentSchedule<T>>::decode_len().unwrap_or(0) as u32;
		if total_blocks == 0 {
			total_blocks = <T::MaxBlocks>::get();
		}
		total_blocks
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Generate dynamic schedule
	/// This function is called by the offchain worker
	/// The following changes are done:
	/// 1. Generate dynamic schedule for dynamic number of rounds
	/// 2. Store the schedule in the storage
	fn generate_dynamic_schedule(bgs_share: Vec<(u32, u32)>, b_max: u32, seed: u32) -> Vec<u32> {
		
		let mut authorities: Vec<u32> = Vec::new();
		let n_authorities: u32 = bgs_share.len() as u32;
		let mut block_count: u32 = 0;
		let mut current_count: Vec<u32> = Vec::new();
		let mut schedule: Vec<u32> = Vec::new();
		let mut author: usize = 10000; // initialize to a value, that is not expected to be valid index

		// initialize authorities and current_count
		for i in 0..bgs_share.len() {
			authorities.push(bgs_share[i].0);
			current_count.push(0u32);
		}
		
		let mut counter: u32 = 0; // to avoid infinite loop
			
		loop {

			if block_count == b_max {
				// if the MAX_BLOCKS is reached exit the loop
				log::trace!("block count {:?}, counter {:?}", block_count, counter);
				break;
			}
			
			// To avoid infinite loop
			if counter > b_max * 2 {
				if block_count != b_max {
				}
				break;
			}
			counter += 1;

			// get the random index from authorities list
			let random_number = Self::generate_random_number(seed);
			let idx: u32 = random_number % n_authorities as u32;
			let authority = authorities[idx as usize] as usize;

			if authority == author {
				// No two consecutive blocks can be autored by same validator/authority
				continue;
			}		
			
			if current_count[idx as usize] >= bgs_share[idx as usize].1 {
				// if the current authority has reached it's max blocks capacity, then continue with the loop
				continue;
			}

			author = authority;
			
			// if all the checks are done and the authority is valid set the schedule
			schedule.push(author as u32); // add to schedule, if the max_blocks allowed is greater than 0
			current_count[idx as usize] += 1;
			block_count += 1;
		}	
		schedule // return dynamic schedule
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Generate random seed
	/// This function is called by offchain worker for generating random number by using the seed
	/// The following changes are done:
	/// 1. Get the random value
	/// 2. Decode the random value
	/// 3. Return the random number
	fn generate_random_seed(seed: [u8; 16]) -> u32 {

		let (random_value, _) = T::PocRandomness::random(&seed);

		let random_number = <u32>::decode(&mut random_value.as_ref())
			.expect("secure hashes should always be bigger than u32; qed");

		random_number // return random number
	}
	
	
	/// W3v PoC Changes, Author: Zubair Buriro
	/// Generate random number
	/// This function is called by offchain worker for generating random number
	/// The following changes are done:
	/// 1. Get the nonce
	/// 2. Get the random value
	/// 3. Decode the random value
	/// 4. Return the random number
	fn generate_random_number(seed: u32) -> u32 {

		let mut nonce = Self::get_and_increment_nonce();
		if seed > 0 {
			let seed_vec = seed.encode();
			nonce = [&mut nonce[..], &seed_vec[..]].concat();
		}

		let (random_value, _) = T::PocRandomness::random(&nonce);

		let random_number = <u32>::decode(&mut random_value.as_ref())
			.expect("secure hashes should always be bigger than u32; qed");

		random_number // return random number
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Get the current round
	/// This function is called on every block
	/// The following changes are done:
	/// 1. Get the current round as param round: u32
	/// 2. Get the authorities for the round
	/// 3. Return the authorities for the round as BoundedVec<u32, T::MaxBlocks>
	fn get_authorities_by_round(round: u32) -> BoundedVec<u32, T::MaxBlocks> {
		// get the schedule by round
		let authorities = NextSchedule::<T>::get(round);
		authorities // return the authorities for the round
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Estimate the next round on every new slot
	fn estimate_next_round() -> u32 {
		
		let current_round = CurrentRound::<T>::get();
		let top_round = TopRound::<T>::get();
		let mut new_round = 0u32;

		if current_round < top_round {
			new_round = current_round.saturating_add(1); // increase round by 1
		}
		new_round
	}

	/// W3v PoC Changes, Author: Zubair Buriro
	/// Get the proposed author
	/// This function is called on every block
	/// The following changes are done:
	/// 1. Get the current round
	/// 2. Get the authorities for the round
	/// 3. Get the current authority by mod function
	/// 4. Get the current proposed author
	/// 5. Return the proposed author as u32 index
	pub fn proposed_author(slot: Slot) -> u32 {
		
		// let genesis_slot  = GenesisSlot::<T>::get();
		let mut current_index = CurrentRoundIdx::<T>::get();
		let current_slot = CurrentSlot::<T>::get();
		let mut current_round = CurrentRound::<T>::get();
		// get lateness and convert it into slot
		//let lateness: u64 = Self::get_lateness().try_into().unwrap_or(0);
		// let diff: Slot = lateness.into();
		// let mut diff: Slot = 0.into();

		log::info!(target: "w3v", "proposed_author: slot {:?}, current_slot {:?}, current_index {:?}, current_round {:?}", slot, current_slot, current_index, current_round);

		if (current_slot != 0u64) && (slot > current_slot) {
			let diff = slot.saturating_sub(current_slot);
			current_index = current_index.wrapping_add(*diff as u32);
		}

		let mut authorities = Self::get_current_schedule();
		let mut idx = current_index % (authorities.len() as u32);

		// check if the current index is greater than the length of the authorities
		// round change is required
		if current_index > 0 && current_index >= (authorities.len() as u32) {
			let new_round = Self::estimate_next_round();
			let current_index = current_index.wrapping_sub(authorities.len() as u32);
			if new_round > 0 {
				// current_index = (*diff as u32).wrapping_sub(1);
				current_round = new_round;
				// get the blocks of the new round
				authorities = Self::get_authorities_by_round(new_round);				
				idx = current_index % (authorities.len() as u32);
			}
		}

		let current_proposed_author = authorities[idx as usize];
		log::info!(target: "w3v", "Block Index: {:?}, proposed_author: {:?}, round: {:?}, slot: {:?}, new_slot: {:?}",
						 idx, current_proposed_author, current_round, current_slot, slot);
		current_proposed_author // return the proposed author index
	}

	/// A helper function to fetch the schedule, sign payload and send an unsigned transaction
	/// Author: Zubair Buriro
	fn offchain_unsigned_tx(
		slot_number: Slot,
		schedule: BoundedVec<u32, T::MaxBlocks>,
	) -> Result<(), &'static str> {
		// Make sure we don't call the function too early
		let next_unsigned_at = <NextUnsignedAt<T>>::get();
		if next_unsigned_at > slot_number {
			return Err("Too early to send unsigned transaction")
		}

		let call = Call::submit_schedule_unsigned { schedule };

		SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
			.map_err(|()| "Failed in offchain_unsigned_tx")?;
		Ok(())
	}

	fn offchain_eip_unsigned_tx(
		_slot: Slot,
		random_number: u32,
		authority_index: u32,
		round: u32,
	) -> Result<(), &'static str> {
		// POC Changes, Author: Zubair Buriro
		// Call the submit_eip_unsigned function as an unsigned transaction
		let call = Call::submit_eip_unsigned { random_number, authority_index, round };

		SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
			.map_err(|()| "Failed in offchain_unsigned_tx")?;
		
		Ok(())
	}


	/// Should we send the transaction
	/// Author: Zubair Buriro
	fn should_send_transaction(block_number: T::BlockNumber, current_round: u32, authority_index: u32) -> bool {
		
		const RECENTLY_SENT: () = ();

		// check if the random is already submitted by this node
		if EIP::<T>::contains_key((current_round, authority_index)) {
			log::info!(target: "w3v", "Should send?: EIP already exists for round: {:?}, authority Index: {:?}", current_round, authority_index);
			false
		} else {
			// Start off by creating a reference to Local Storage value.
			let val = StorageValueRef::persistent(b"poc_ocw::last_send");
			// To persist the last send block number
			let res = val.mutate(|last_send: Result<Option<T::BlockNumber>, StorageRetrievalError>| {
				match last_send {
					// If we already have a value in storage and the block number is recent enough
					// we avoid sending another transaction at this time.
					Ok(Some(block)) if block_number < block + T::GracePeriod::get() =>
						Err(RECENTLY_SENT),
					// In every other case we attempt to acquire the lock and send a transaction.
					_ => Ok(block_number),
				}
			});

			match res {
				// The value has been set correctly, which means we can safely send a transaction now.
				Ok(_block_number) => {
					true
				},
				// We are in the grace period, we should not send a transaction this time.
				Err(MutateStorageError::ValueFunctionFailed(RECENTLY_SENT)) => false,
				
				// We failed to acquire the lock, which means another offchain worker is currently
				Err(MutateStorageError::ConcurrentModification(_)) => false,
			}
		}
	}


	fn print_authorities(authorities: Vec<u32>, _round: u32) {
		// authorities		
		let babe_authorities = Authorities::<T>::get();

		for idx in authorities {
			log::info!(target: "w3v", "Authority Index: {:?}, Authority: {:?}", idx, babe_authorities[idx as usize].0);
    	}
	}

	// ** w3v poc changes end */

	/// Determine the BABE slot duration based on the Timestamp module configuration.
	pub fn slot_duration() -> T::Moment {
		// we double the minimum block-period so each author can always propose within
		// the majority of their slot.
		<T as pallet_timestamp::Config>::MinimumPeriod::get().saturating_mul(2u32.into())
	}

	/// Determine whether an epoch change should take place at this block.
	/// Assumes that initialization has already taken place.
	pub fn should_epoch_change(now: T::BlockNumber) -> bool {
		// The epoch has technically ended during the passage of time
		// between this block and the last, but we have to "end" the epoch now,
		// since there is no earlier possible block we could have done it.
		//
		// The exception is for block 1: the genesis has slot 0, so we treat
		// epoch 0 as having started at the slot of block 1. We want to use
		// the same randomness and validator set as signalled in the genesis,
		// so we don't rotate the epoch.
		now != One::one() && {
			let diff = CurrentSlot::<T>::get().saturating_sub(Self::current_epoch_start());
			*diff >= T::EpochDuration::get()
		}
	}

	/// Return the _best guess_ block number, at which the next epoch change is predicted to happen.
	///
	/// Returns None if the prediction is in the past; This implies an error internally in the Babe
	/// and should not happen under normal circumstances.
	///
	/// In other word, this is only accurate if no slots are missed. Given missed slots, the slot
	/// number will grow while the block number will not. Hence, the result can be interpreted as an
	/// upper bound.
	// ## IMPORTANT NOTE
	//
	// This implementation is linked to how [`should_epoch_change`] is working. This might need to
	// be updated accordingly, if the underlying mechanics of slot and epochs change.
	//
	// WEIGHT NOTE: This function is tied to the weight of `EstimateNextSessionRotation`. If you
	// update this function, you must also update the corresponding weight.
	pub fn next_expected_epoch_change(now: T::BlockNumber) -> Option<T::BlockNumber> {
		let next_slot = Self::current_epoch_start().saturating_add(T::EpochDuration::get());
		next_slot.checked_sub(*CurrentSlot::<T>::get()).map(|slots_remaining| {
			// This is a best effort guess. Drifts in the slot/block ratio will cause errors here.
			let blocks_remaining: T::BlockNumber = slots_remaining.saturated_into();
			now.saturating_add(blocks_remaining)
		})
	}

	/// DANGEROUS: Enact an epoch change. Should be done on every block where `should_epoch_change`
	/// has returned `true`, and the caller is the only caller of this function.
	///
	/// Typically, this is not handled directly by the user, but by higher-level validator-set
	/// manager logic like `pallet-session`.
	///
	/// This doesn't do anything if `authorities` is empty.
	pub fn enact_epoch_change(
		authorities: WeakBoundedVec<(AuthorityId, BabeAuthorityWeight), T::MaxAuthorities>,
		next_authorities: WeakBoundedVec<(AuthorityId, BabeAuthorityWeight), T::MaxAuthorities>,
	) {
		// PRECONDITION: caller has done initialization and is guaranteed
		// by the session module to be called before this.
		debug_assert!(Self::initialized().is_some());

		if authorities.is_empty() {
			log::warn!(target: LOG_TARGET, "Ignoring empty epoch change.");

			return
		}

		// Update epoch index.
		//
		// NOTE: we figure out the epoch index from the slot, which may not
		// necessarily be contiguous if the chain was offline for more than
		// `T::EpochDuration` slots. When skipping from epoch N to e.g. N+4, we
		// will be using the randomness and authorities for that epoch that had
		// been previously announced for epoch N+1, and the randomness collected
		// during the current epoch (N) will be used for epoch N+5.
		let epoch_index = sp_consensus_babe::epoch_index(
			CurrentSlot::<T>::get(),
			GenesisSlot::<T>::get(),
			T::EpochDuration::get(),
		);

		EpochIndex::<T>::put(epoch_index);
		Authorities::<T>::put(authorities);

		// Update epoch randomness.
		let next_epoch_index = epoch_index
			.checked_add(1)
			.expect("epoch indices will never reach 2^64 before the death of the universe; qed");

		// Returns randomness for the current epoch and computes the *next*
		// epoch randomness.
		let randomness = Self::randomness_change_epoch(next_epoch_index);
		Randomness::<T>::put(randomness);

		// Update the next epoch authorities.
		NextAuthorities::<T>::put(&next_authorities);

		// Update the start blocks of the previous and new current epoch.
		<EpochStart<T>>::mutate(|(previous_epoch_start_block, current_epoch_start_block)| {
			*previous_epoch_start_block = sp_std::mem::take(current_epoch_start_block);
			*current_epoch_start_block = <frame_system::Pallet<T>>::block_number();
		});

		// After we update the current epoch, we signal the *next* epoch change
		// so that nodes can track changes.
		let next_randomness = NextRandomness::<T>::get();

		let next_epoch = NextEpochDescriptor {
			authorities: next_authorities.to_vec(),
			randomness: next_randomness,
		};
		Self::deposit_consensus(ConsensusLog::NextEpochData(next_epoch));

		if let Some(next_config) = NextEpochConfig::<T>::get() {
			EpochConfig::<T>::put(next_config);
		}

		if let Some(pending_epoch_config_change) = PendingEpochConfigChange::<T>::take() {
			let next_epoch_config: BabeEpochConfiguration =
				pending_epoch_config_change.clone().into();
			NextEpochConfig::<T>::put(next_epoch_config);

			Self::deposit_consensus(ConsensusLog::NextConfigData(pending_epoch_config_change));
		}
	}

	/// Finds the start slot of the current epoch.
	///
	/// Only guaranteed to give correct results after `initialize` of the first
	/// block in the chain (as its result is based off of `GenesisSlot`).
	pub fn current_epoch_start() -> Slot {
		sp_consensus_babe::epoch_start_slot(
			EpochIndex::<T>::get(),
			GenesisSlot::<T>::get(),
			T::EpochDuration::get(),
		)
	}

	/// Produces information about the current epoch.
	pub fn current_epoch() -> Epoch {
		Epoch {
			epoch_index: EpochIndex::<T>::get(),
			start_slot: Self::current_epoch_start(),
			duration: T::EpochDuration::get(),
			authorities: Self::authorities().to_vec(),
			randomness: Self::randomness(),
			config: EpochConfig::<T>::get()
				.expect("EpochConfig is initialized in genesis; we never `take` or `kill` it; qed"),
		}
	}

	/// Produces information about the next epoch (which was already previously
	/// announced).
	pub fn next_epoch() -> Epoch {
		let next_epoch_index = EpochIndex::<T>::get().checked_add(1).expect(
			"epoch index is u64; it is always only incremented by one; \
			 if u64 is not enough we should crash for safety; qed.",
		);

		let start_slot = sp_consensus_babe::epoch_start_slot(
			next_epoch_index,
			GenesisSlot::<T>::get(),
			T::EpochDuration::get(),
		);

		Epoch {
			epoch_index: next_epoch_index,
			start_slot,
			duration: T::EpochDuration::get(),
			authorities: NextAuthorities::<T>::get().to_vec(),
			randomness: NextRandomness::<T>::get(),
			config: NextEpochConfig::<T>::get().unwrap_or_else(|| {
				EpochConfig::<T>::get().expect(
					"EpochConfig is initialized in genesis; we never `take` or `kill` it; qed",
				)
			}),
		}
	}

	fn deposit_consensus<U: Encode>(new: U) {
		let log = DigestItem::Consensus(BABE_ENGINE_ID, new.encode());
		<frame_system::Pallet<T>>::deposit_log(log)
	}

	fn deposit_randomness(randomness: &schnorrkel::Randomness) {
		let segment_idx = SegmentIndex::<T>::get();
		let mut segment = UnderConstruction::<T>::get(&segment_idx);
		if segment.try_push(*randomness).is_ok() {
			// push onto current segment: not full.
			UnderConstruction::<T>::insert(&segment_idx, &segment);
		} else {
			// move onto the next segment and update the index.
			let segment_idx = segment_idx + 1;
			let bounded_randomness =
				BoundedVec::<_, ConstU32<UNDER_CONSTRUCTION_SEGMENT_LENGTH>>::try_from(vec![
					*randomness,
				])
				.expect("UNDER_CONSTRUCTION_SEGMENT_LENGTH >= 1");
			UnderConstruction::<T>::insert(&segment_idx, bounded_randomness);
			SegmentIndex::<T>::put(&segment_idx);
		}
	}

	fn initialize_genesis_authorities(authorities: &[(AuthorityId, BabeAuthorityWeight)]) {
		if !authorities.is_empty() {
			assert!(Authorities::<T>::get().is_empty(), "Authorities are already initialized!");
			let bounded_authorities =
				WeakBoundedVec::<_, T::MaxAuthorities>::try_from(authorities.to_vec())
					.expect("Initial number of authorities should be lower than T::MaxAuthorities");
			Authorities::<T>::put(&bounded_authorities);
			NextAuthorities::<T>::put(&bounded_authorities);

			// ** w3v poc changes ** /
			//log::info!(target: "w3v", "Poc Authority: {:?}", bounded_authorities.clone());
			// let bounded_poc_authorities =
			//	BoundedVec::<_, T::MaxAuthorities>::try_from(poc_authorities.to_vec())
			//			.expect("Initial number of authorities should be lower than T::MaxAuthorities");
			// <PocAuthorities<T>>::put(&bounded_poc_authorities);
			// set current round to 0
			<CurrentRound<T>>::put(0u32);
			<TopRound<T>>::put(0u32); // set top round to 0
			
			

			// Call function to generate static schedule for once
			let _schedule = Self::generate_static_schedule(); // this line is added
			// ** w3v poc changes end  ** /
		}
	}

	fn initialize_genesis_epoch(genesis_slot: Slot) {
		GenesisSlot::<T>::put(genesis_slot);
		debug_assert_ne!(*GenesisSlot::<T>::get(), 0);

		// deposit a log because this is the first block in epoch #0
		// we use the same values as genesis because we haven't collected any
		// randomness yet.
		let next = NextEpochDescriptor {
			authorities: Self::authorities().to_vec(),
			randomness: Self::randomness(),
		};

		Self::deposit_consensus(ConsensusLog::NextEpochData(next));
	}

	fn initialize(now: T::BlockNumber) {
		// since `initialize` can be called twice (e.g. if session module is present)
		// let's ensure that we only do the initialization once per block
		let initialized = Self::initialized().is_some();
		if initialized {
			return
		}

		let pre_digest =
			<frame_system::Pallet<T>>::digest()
				.logs
				.iter()
				.filter_map(|s| s.as_pre_runtime())
				.filter_map(|(id, mut data)| {
					if id == BABE_ENGINE_ID {
						PreDigest::decode(&mut data).ok()
					} else {
						None
					}
				})
				.next();

		if let Some(ref pre_digest) = pre_digest {
			// the slot number of the current block being initialized
			let current_slot = pre_digest.slot();

			// on the first non-zero block (i.e. block #1)
			// this is where the first epoch (epoch #0) actually starts.
			// we need to adjust internal storage accordingly.
			if *GenesisSlot::<T>::get() == 0 {
				Self::initialize_genesis_epoch(current_slot)
			}

			// how many slots were skipped between current and last block
			let lateness = current_slot.saturating_sub(CurrentSlot::<T>::get() + 1);
			let lateness = T::BlockNumber::from(*lateness as u32);

			Lateness::<T>::put(lateness);
			CurrentSlot::<T>::put(current_slot);
		}

		Initialized::<T>::put(pre_digest);

		// enact epoch change, if necessary.
		T::EpochChangeTrigger::trigger::<T>(now);
	}

	/// Call this function exactly once when an epoch changes, to update the
	/// randomness. Returns the new randomness.
	fn randomness_change_epoch(next_epoch_index: u64) -> schnorrkel::Randomness {
		let this_randomness = NextRandomness::<T>::get();
		let segment_idx: u32 = SegmentIndex::<T>::mutate(|s| sp_std::mem::replace(s, 0));

		// overestimate to the segment being full.
		let rho_size = (segment_idx.saturating_add(1) * UNDER_CONSTRUCTION_SEGMENT_LENGTH) as usize;

		let next_randomness = compute_randomness(
			this_randomness,
			next_epoch_index,
			(0..segment_idx).flat_map(|i| UnderConstruction::<T>::take(&i)),
			Some(rho_size),
		);
		NextRandomness::<T>::put(&next_randomness);
		this_randomness
	}

	fn do_report_equivocation(
		reporter: Option<T::AccountId>,
		equivocation_proof: EquivocationProof<T::Header>,
		key_owner_proof: T::KeyOwnerProof,
	) -> DispatchResultWithPostInfo {
		let offender = equivocation_proof.offender.clone();
		let slot = equivocation_proof.slot;

		// validate the equivocation proof
		if !sp_consensus_babe::check_equivocation_proof(equivocation_proof) {
			return Err(Error::<T>::InvalidEquivocationProof.into())
		}

		let validator_set_count = key_owner_proof.validator_count();
		let session_index = key_owner_proof.session();

		let epoch_index = (*slot.saturating_sub(GenesisSlot::<T>::get()) / T::EpochDuration::get())
			.saturated_into::<u32>();

		// check that the slot number is consistent with the session index
		// in the key ownership proof (i.e. slot is for that epoch)
		if epoch_index != session_index {
			return Err(Error::<T>::InvalidKeyOwnershipProof.into())
		}

		// check the membership proof and extract the offender's id
		let key = (sp_consensus_babe::KEY_TYPE, offender);
		let offender = T::KeyOwnerProofSystem::check_proof(key, key_owner_proof)
			.ok_or(Error::<T>::InvalidKeyOwnershipProof)?;

		let offence =
			BabeEquivocationOffence { slot, validator_set_count, offender, session_index };

		let reporters = match reporter {
			Some(id) => vec![id],
			None => vec![],
		};

		T::HandleEquivocation::report_offence(reporters, offence)
			.map_err(|_| Error::<T>::DuplicateOffenceReport)?;

		// waive the fee since the report is valid and beneficial
		Ok(Pays::No.into())
	}

	/// Submits an extrinsic to report an equivocation. This method will create
	/// an unsigned extrinsic with a call to `report_equivocation_unsigned` and
	/// will push the transaction to the pool. Only useful in an offchain
	/// context.
	pub fn submit_unsigned_equivocation_report(
		equivocation_proof: EquivocationProof<T::Header>,
		key_owner_proof: T::KeyOwnerProof,
	) -> Option<()> {
		T::HandleEquivocation::submit_unsigned_equivocation_report(
			equivocation_proof,
			key_owner_proof,
		)
		.ok()
	}
}

impl<T: Config> OnTimestampSet<T::Moment> for Pallet<T> {
	fn on_timestamp_set(moment: T::Moment) {
		let slot_duration = Self::slot_duration();
		assert!(!slot_duration.is_zero(), "Babe slot duration cannot be zero.");

		let timestamp_slot = moment / slot_duration;
		let timestamp_slot = Slot::from(timestamp_slot.saturated_into::<u64>());

		assert!(
			CurrentSlot::<T>::get() == timestamp_slot,
			"Timestamp slot must match `CurrentSlot`"
		);
	}
}

impl<T: Config> frame_support::traits::EstimateNextSessionRotation<T::BlockNumber> for Pallet<T> {
	fn average_session_length() -> T::BlockNumber {
		T::EpochDuration::get().saturated_into()
	}

	fn estimate_current_session_progress(_now: T::BlockNumber) -> (Option<Permill>, Weight) {
		let elapsed = CurrentSlot::<T>::get().saturating_sub(Self::current_epoch_start()) + 1;

		(
			Some(Permill::from_rational(*elapsed, T::EpochDuration::get())),
			// Read: Current Slot, Epoch Index, Genesis Slot
			T::DbWeight::get().reads(3),
		)
	}

	fn estimate_next_session_rotation(now: T::BlockNumber) -> (Option<T::BlockNumber>, Weight) {
		(
			Self::next_expected_epoch_change(now),
			// Read: Current Slot, Epoch Index, Genesis Slot
			T::DbWeight::get().reads(3),
		)
	}
}

impl<T: Config> frame_support::traits::Lateness<T::BlockNumber> for Pallet<T> {
	fn lateness(&self) -> T::BlockNumber {
		Self::lateness()
	}
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T> {
	type Public = AuthorityId;
}

impl<T: Config> OneSessionHandler<T::AccountId> for Pallet<T> {
	type Key = AuthorityId;

	fn on_genesis_session<'a, I: 'a>(validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, AuthorityId)>,
	{
		let authorities = validators.map(|(_, k)| (k, 1)).collect::<Vec<_>>();
		Self::initialize_genesis_authorities(&authorities);
	}

	fn on_new_session<'a, I: 'a>(_changed: bool, validators: I, queued_validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, AuthorityId)>,
	{
		let authorities = validators.map(|(_account, k)| (k, 1)).collect::<Vec<_>>();
		let bounded_authorities = WeakBoundedVec::<_, T::MaxAuthorities>::force_from(
			authorities,
			Some(
				"Warning: The session has more validators than expected. \
				A runtime configuration adjustment may be needed.",
			),
		);

		let next_authorities = queued_validators.map(|(_account, k)| (k, 1)).collect::<Vec<_>>();
		let next_bounded_authorities = WeakBoundedVec::<_, T::MaxAuthorities>::force_from(
			next_authorities,
			Some(
				"Warning: The session has more queued validators than expected. \
				A runtime configuration adjustment may be needed.",
			),
		);

		Self::enact_epoch_change(bounded_authorities, next_bounded_authorities)
	}

	fn on_disabled(i: u32) {
		Self::deposit_consensus(ConsensusLog::OnDisabled(i))
	}
}

// compute randomness for a new epoch. rho is the concatenation of all
// VRF outputs in the prior epoch.
//
// an optional size hint as to how many VRF outputs there were may be provided.
fn compute_randomness(
	last_epoch_randomness: schnorrkel::Randomness,
	epoch_index: u64,
	rho: impl Iterator<Item = schnorrkel::Randomness>,
	rho_size_hint: Option<usize>,
) -> schnorrkel::Randomness {
	let mut s = Vec::with_capacity(40 + rho_size_hint.unwrap_or(0) * VRF_OUTPUT_LENGTH);
	s.extend_from_slice(&last_epoch_randomness);
	s.extend_from_slice(&epoch_index.to_le_bytes());

	for vrf_output in rho {
		s.extend_from_slice(&vrf_output[..]);
	}

	sp_io::hashing::blake2_256(&s)
}

pub mod migrations {
	use super::*;
	use frame_support::pallet_prelude::{StorageValue, ValueQuery};

	/// Something that can return the storage prefix of the `Babe` pallet.
	pub trait BabePalletPrefix: Config {
		fn pallet_prefix() -> &'static str;
	}

	struct __OldNextEpochConfig<T>(sp_std::marker::PhantomData<T>);
	impl<T: BabePalletPrefix> frame_support::traits::StorageInstance for __OldNextEpochConfig<T> {
		fn pallet_prefix() -> &'static str {
			T::pallet_prefix()
		}
		const STORAGE_PREFIX: &'static str = "NextEpochConfig";
	}

	type OldNextEpochConfig<T> =
		StorageValue<__OldNextEpochConfig<T>, Option<NextConfigDescriptor>, ValueQuery>;

	/// A storage migration that adds the current epoch configuration for Babe
	/// to storage.
	pub fn add_epoch_configuration<T: BabePalletPrefix>(
		epoch_config: BabeEpochConfiguration,
	) -> Weight {
		let mut writes = 0;
		let mut reads = 0;

		if let Some(pending_change) = OldNextEpochConfig::<T>::get() {
			PendingEpochConfigChange::<T>::put(pending_change);

			writes += 1;
		}

		reads += 1;

		OldNextEpochConfig::<T>::kill();

		EpochConfig::<T>::put(epoch_config.clone());
		NextEpochConfig::<T>::put(epoch_config);

		writes += 3;

		T::DbWeight::get().reads_writes(reads, writes)
	}
}
