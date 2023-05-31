//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

// use crate::cli::Cli;
use crate::{
	cli::{ Cli, Sealing, },
	// client::{BaseRuntimeApiCollection, FullBackend, FullClient, RuntimeApiCollection},
	client::{BaseRuntimeApiCollection, FullBackend, RuntimeApiCollection},
	eth::{
		new_frontier_partial, spawn_frontier_tasks, FrontierBackend, FrontierBlockImport,
		FrontierPartialComponents,
	},
}; 
use std::{
	collections::BTreeMap,
	path::PathBuf,
	sync::{Arc, Mutex},
	time::Duration,
};
use sp_trie::PrefixedMemoryDB;
pub use crate::{
	client::{Client as FullClient, TemplateRuntimeExecutor},
	eth::{db_config_dir, EthConfiguration},
};

// use futures::{future, StreamExt};
use futures::{channel::mpsc, prelude::*};
// Substrate
use sc_cli::SubstrateCli;
use sc_client_api::{BlockBackend, BlockchainEvents};
use sc_consensus:: { BasicQueue };
use sc_consensus_babe::{self, SlotProportion};
pub use sc_executor::{ NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_finality_grandpa::SharedVoterState;
// use sc_keystore::LocalKeystore;
use sp_core::{ U256 };
use sc_service::{error::Error as ServiceError, BasePath, Configuration, TaskManager, PartialComponents};
use sc_telemetry::{Telemetry, TelemetryWorker, TelemetryHandle};
use sp_runtime::traits::{ Block as BlockT, BlakeTwo256 };
use sp_api::{ConstructRuntimeApi, TransactionFor};
// Frontier
//use fc_db::Backend as FrontierBackend;
use fc_mapping_sync::{MappingSyncWorker, SyncStrategy};
use fc_rpc::{EthTask, OverrideHandle};
use fc_rpc_core::types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool};
// Runtime
use frontier_template_runtime::{self, opaque::Block, RuntimeApi, TransactionConverter};

// Our native executor instance.

/*
pub struct ExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
	/// Only enable the benchmarking host functions when we actually want to benchmark.
	#[cfg(feature = "runtime-benchmarks")]
	type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
	/// Otherwise we only use the default Substrate host functions.
	#[cfg(not(feature = "runtime-benchmarks"))]
	type ExtendHostFunctions = ();

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		frontier_template_runtime::api::dispatch(method, data)
	}

	fn native_version() -> sc_executor::NativeVersion {
		frontier_template_runtime::native_version()
	}
}
*/

type BasicImportQueue<Client> = sc_consensus::DefaultImportQueue<Block, Client>;
type FullPool<Client> = sc_transaction_pool::FullPool<Block, Client>;
type BoxBlockImport<Client> = sc_consensus::BoxBlockImport<Block, TransactionFor<Client, Block>>;

//pub type FullClient =
//	sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
// type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport =
	sc_finality_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>;

/*
pub(crate) fn db_config_dir(config: &Configuration) -> PathBuf {
	config
		.base_path
		.as_ref()
		.map(|base_path| base_path.config_dir(config.chain_spec.id()))
		.unwrap_or_else(|| {
			BasePath::from_project("", "", &Cli::executable_name())
				.config_dir(config.chain_spec.id())
		})
}
*/

pub fn new_partial(
	config: &Configuration,
	eth_config: &EthConfiguration,
) -> Result<
	sc_service::PartialComponents<
		FullClient,
		FullBackend,
		FullSelectChain,
		sc_consensus::DefaultImportQueue<Block, FullClient>,
		sc_transaction_pool::FullPool<Block, FullClient>,
		(
			Option<Telemetry>,
			(
				sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
				sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
				sc_consensus_babe::BabeLink<Block>,
			),
			Arc<FrontierBackend>,
			//Option<FilterPool>,
			//(FeeHistoryCache, FeeHistoryCacheLimit),
		),
	>,
	ServiceError,
> {
	/*
	if config.keystore_remote.is_some() {
		return Err(ServiceError::Other(
			"Remote Keystores are not supported.".to_string(),
		));
	}
	*/

	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = NativeElseWasmExecutor::<TemplateRuntimeExecutor>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
		config.runtime_cache_size,
	);

	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
		client.clone(),
		&client,
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let justification_import = grandpa_block_import.clone();

	let (block_import, babe_link) = sc_consensus_babe::block_import(
		sc_consensus_babe::configuration(&*client)?,
		grandpa_block_import.clone(),
		client.clone(),
	)?;

	let slot_duration = babe_link.config().slot_duration();

	
	let frontier_backend = Arc::new(FrontierBackend::open(
		client.clone(),
		&config.database,
		&db_config_dir(config),
	)?);

	/*
	let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));
	let fee_history_cache: FeeHistoryCache = Arc::new(Mutex::new(BTreeMap::new()));
	let fee_history_cache_limit: FeeHistoryCacheLimit = cli.run.fee_history_limit;
	*/

	let import_queue = sc_consensus_babe::import_queue(
		babe_link.clone(),
		block_import.clone(),
		Some(Box::new(justification_import)),
		client.clone(),
		select_chain.clone(),
		move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

			let slot =
				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
					*timestamp,
					slot_duration,
				);

			//let uncles =
			//	sp_authorship::InherentDataProvider::<<Block as BlockT>::Header>::check_inherents();

			Ok((slot, timestamp))
		},
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let import_setup = (block_import, grandpa_link, babe_link);
	
	// let fee_history = (fee_history_cache, fee_history_cache_limit);

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	Ok(sc_service::PartialComponents {
		client,
		backend,
		keystore_container,
		task_manager,
		select_chain,
		import_queue,
		transaction_pool,
		other: (telemetry, import_setup, frontier_backend),
		//other: (telemetry, import_setup, frontier_backend),
	})
}

/*
fn remote_keystore(_url: &str) -> Result<Arc<LocalKeystore>, &'static str> {
	// FIXME: here would the concrete keystore be built,
	//        must return a concrete type (NOT `LocalKeystore`) that
	//        implements `CryptoStore` and `SyncCryptoStore`
	Err("Remote Keystore not supported.")
}
*/


/// Builds a new service for a full client.
pub fn new_full(
	mut config: Configuration,
	eth_config: EthConfiguration,
	sealing: Option<Sealing>,
) -> Result<TaskManager, ServiceError> {
	let sc_service::PartialComponents {
		client,
		backend,
		keystore_container,
		mut task_manager,
		select_chain,
		import_queue,
		transaction_pool,
		other:
			(
				mut telemetry,
				import_setup,
				frontier_backend,
				//filter_pool,
				//fee_history,
			),
	} = new_partial(&config, &eth_config)?;

	let (block_import, grandpa_link, babe_link) = import_setup;

	/*
	if let Some(url) = &config.keystore_remote {
		match remote_keystore(url) {
			Ok(k) => keystore_container.set_remote_keystore(k),
			Err(e) => {
				return Err(ServiceError::Other(format!(
					"Error hooking up remote keystore for {}: {}",
					url, e
				)))
			}
		};
	}
	*/
	
	let FrontierPartialComponents {
		filter_pool,
		fee_history_cache,
		fee_history_cache_limit,
	} = new_frontier_partial(&eth_config)?;
	

	let grandpa_protocol_name = sc_finality_grandpa::protocol_standard_name(
		&client
			.block_hash(0)?
			//.ok()
			//.flatten()
			.expect("Genesis block exists; qed"),
		&config.chain_spec,
	);

	let warp_sync: Option<Arc<dyn sc_network::config::WarpSyncProvider<Block>>> =
		if sealing.is_some() {
			None
		} else {
			config
				.network
				.extra_sets
				.push(sc_finality_grandpa::grandpa_peers_set_config(
					grandpa_protocol_name.clone(),
				));
			Some(Arc::new(
				sc_finality_grandpa::warp_proof::NetworkProvider::new(
					backend.clone(),
					grandpa_link.shared_authority_set().clone(),
					Vec::default(),
				),
			))
		};

	/*
	config
		.network
		.extra_sets
		.push(sc_finality_grandpa::grandpa_peers_set_config(
			grandpa_protocol_name.clone(),
		));
	let warp_sync = Arc::new(sc_finality_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		import_setup.1.shared_authority_set().clone(),
		Vec::default(),
	));
	*/



	let (network, system_rpc_tx, tx_handler_controller, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync,
		})?;

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			task_manager.spawn_handle(),
			client.clone(),
			network.clone(),
		);
	}

	let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa && sealing.is_none();
	let prometheus_registry = config.prometheus_registry().cloned();

	// Channel for the rpc handler to communicate with the authorship task.
	let (command_sink, commands_stream) = mpsc::channel(1000);

	// for ethereum-compatibility rpc.
	config.rpc_id_provider = Some(Box::new(fc_rpc::EthereumSubIdProvider));
	let overrides = crate::rpc::overrides_handle(client.clone());
	let eth_rpc_params = crate::rpc::EthDeps {
		client: client.clone(),
		pool: transaction_pool.clone(),
		graph: transaction_pool.pool().clone(),
		converter: Some(TransactionConverter),
		is_authority: config.role.is_authority(),
		enable_dev_signer: eth_config.enable_dev_signer,
		network: network.clone(),
		frontier_backend: frontier_backend.clone(),
		overrides: overrides.clone(),
		block_data_cache: Arc::new(fc_rpc::EthBlockDataCacheTask::new(
			task_manager.spawn_handle(),
			overrides.clone(),
			eth_config.eth_log_block_cache,
			eth_config.eth_statuses_cache,
			prometheus_registry.clone(),
		)),
		filter_pool: filter_pool.clone(),
		max_past_logs: eth_config.max_past_logs,
		fee_history_cache: fee_history_cache.clone(),
		fee_history_cache_limit,
		execute_gas_limit_multiplier: eth_config.execute_gas_limit_multiplier,
	};
	
	/*
	let overrides = crate::rpc::overrides_handle(client.clone());
	let block_data_cache = Arc::new(fc_rpc::EthBlockDataCacheTask::new(
		task_manager.spawn_handle(),
		overrides.clone(),
		50,
		50,
		prometheus_registry.clone(),
	));

	let (fee_history_cache, fee_history_cache_limit) = fee_history;
	

	let rpc_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();
		let is_authority = role.is_authority();
		let enable_dev_signer = cli.run.enable_dev_signer;
		let network = network.clone();
		let filter_pool = filter_pool.clone();
		let frontier_backend = frontier_backend.clone();
		let overrides = overrides.clone();
		let fee_history_cache = fee_history_cache.clone();
		let max_past_logs = cli.run.max_past_logs;

		Box::new(move |deny_unsafe, subscription_task_executor| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				graph: pool.pool().clone(),
				deny_unsafe,
				is_authority,
				enable_dev_signer,
				network: network.clone(),
				filter_pool: filter_pool.clone(),
				backend: frontier_backend.clone(),
				//max_past_logs,
				//fee_history_cache: fee_history_cache.clone(),
				//fee_history_cache_limit,
				overrides: overrides.clone(),
				block_data_cache: block_data_cache.clone(),
			};

			crate::rpc::create_full(deps, subscription_task_executor).map_err(Into::into)
		})
	};
	*/

	let rpc_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();

		Box::new(move |deny_unsafe, subscription_task_executor| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				deny_unsafe,
				command_sink: if sealing.is_some() {
					Some(command_sink.clone())
				} else {
					None
				},
				eth: eth_rpc_params.clone(),
			};

			crate::rpc::create_full(deps, subscription_task_executor).map_err(Into::into)
		})
	};

	let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		config,
		client: client.clone(),
		backend: backend.clone(),
		task_manager: &mut task_manager,
		keystore: keystore_container.sync_keystore(),
		transaction_pool: transaction_pool.clone(),
		rpc_builder,
		network: network.clone(),
		system_rpc_tx,
		tx_handler_controller,
		telemetry: telemetry.as_mut(),
	})?;

	spawn_frontier_tasks(
		&task_manager,
		client.clone(),
		backend,
		frontier_backend,
		filter_pool,
		overrides,
		fee_history_cache,
		fee_history_cache_limit,
	);

	

	if role.is_authority() {
		let proposer_factory = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let target_gas_price = eth_config.target_gas_price;
		let slot_duration = babe_link.config().slot_duration();
		
		let create_inherent_data_providers = move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
			let slot = sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
				*timestamp,
				slot_duration,
			);
			let dynamic_fee = fp_dynamic_fee::InherentDataProvider(U256::from(target_gas_price));
			Ok((slot, timestamp, dynamic_fee))
		};

		//let client_clone = client.clone();
		
		let babe_config = sc_consensus_babe::BabeParams {
			keystore: keystore_container.sync_keystore(),
			client: client.clone(),
			select_chain,
			env: proposer_factory,
			block_import,
			sync_oracle: network.clone(),
			justification_sync_link: network.clone(),
			create_inherent_data_providers,
			force_authoring,
			backoff_authoring_blocks: Option::<()>::None,
			babe_link,
			block_proposal_slot_portion: SlotProportion::new(0.5),
			max_block_proposal_slot_portion: None,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};
		
		let babe = sc_consensus_babe::start_babe(babe_config)?;
		task_manager.spawn_essential_handle().spawn_blocking(
			"babe-proposer",
			Some("block-authoring"),
			babe
		);
	}


	if enable_grandpa {

		// if the node isn't actively participating in consensus then it doesn't
		// need a keystore, regardless of which protocol we use below.
		let keystore = if role.is_authority() { 
			Some(keystore_container.sync_keystore()) 
		} else { 
			None 
		};

		let grandpa_config = sc_finality_grandpa::Config {
			// FIXME #1578 make this available through chainspec
			gossip_duration: Duration::from_millis(333),
			justification_period: 512,
			name: Some(name),
			observer_enabled: false,
			keystore,
			local_role: role,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			protocol_name: grandpa_protocol_name,
		};
		// start the full GRANDPA voter
		// NOTE: non-authorities could run the GRANDPA observer protocol, but at
		// this point the full voter should provide better guarantees of block
		// and vote data availability than the observer. The observer has not
		// been tested extensively yet and having most nodes in a network run it
		// could lead to finality stalls.
		let grandpa_voter =
			sc_finality_grandpa::run_grandpa_voter(sc_finality_grandpa::GrandpaParams {
				config: grandpa_config,
				link: grandpa_link,
				network,
				voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
				prometheus_registry,
				shared_voter_state: sc_finality_grandpa::SharedVoterState::empty(),
				telemetry: telemetry.as_ref().map(|x| x.handle()),
		})?;

		// the GRANDPA voter task is considered infallible, i.e.
		// if it fails we take down the service with it.
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("grandpa-voter", None, grandpa_voter);
	}

	network_starter.start_network();
	Ok(task_manager)
}

/*
fn spawn_frontier_tasks(
	task_manager: &TaskManager,
	client: Arc<FullClient>,
	backend: Arc<FullBackend>,
	frontier_backend: Arc<FrontierBackend<Block>>,
	filter_pool: Option<FilterPool>,
	overrides: Arc<OverrideHandle<Block>>,
	fee_history_cache: FeeHistoryCache,
	fee_history_cache_limit: FeeHistoryCacheLimit,
) {
	task_manager.spawn_essential_handle().spawn(
		"frontier-mapping-sync-worker",
		None,
		MappingSyncWorker::new(
			client.import_notification_stream(),
			Duration::new(6, 0),
			client.clone(),
			backend,
			frontier_backend,
			3,
			0,
			SyncStrategy::Normal,
		)
		.for_each(|()| future::ready(())),
	);

	// Spawn Frontier EthFilterApi maintenance task.
	if let Some(filter_pool) = filter_pool {
		// Each filter is allowed to stay in the pool for 100 blocks.
		const FILTER_RETAIN_THRESHOLD: u64 = 100;
		task_manager.spawn_essential_handle().spawn(
			"frontier-filter-pool",
			None,
			EthTask::filter_pool_task(client.clone(), filter_pool, FILTER_RETAIN_THRESHOLD),
		);
	}

	// Spawn Frontier FeeHistory cache maintenance task.
	task_manager.spawn_essential_handle().spawn(
		"frontier-fee-history",
		None,
		EthTask::fee_history_task(
			client,
			overrides,
			fee_history_cache,
			fee_history_cache_limit,
		),
	);
}
*/
pub fn build_full(
	config: Configuration,
	eth_config: EthConfiguration,
	sealing: Option<Sealing>,
) -> Result<TaskManager, ServiceError> {
	//new_full::<frontier_template_runtime::RuntimeApi, TemplateRuntimeExecutor>(
	new_full(
		config, eth_config, sealing,
	)
}

pub fn new_chain_ops(
	mut config: &mut Configuration,
	eth_config: &EthConfiguration,
) -> Result<
	(
		Arc<FullClient>,
		Arc<FullBackend>,
		BasicQueue<Block, PrefixedMemoryDB<BlakeTwo256>>,
		TaskManager,
		Arc<FrontierBackend>,
	),
	ServiceError,
> {
	config.keystore = sc_service::config::KeystoreConfig::InMemory;
	let PartialComponents {
		client,
		backend,
		import_queue,
		task_manager,
		other,
		..
	// } = new_partial::<frontier_template_runtime::RuntimeApi, TemplateRuntimeExecutor, _>(
	} = new_partial(
		config,
		eth_config,
		// build_babe_grandpa_import_queue,
	)?;
	Ok((client, backend, import_queue, task_manager, other.2))
}

