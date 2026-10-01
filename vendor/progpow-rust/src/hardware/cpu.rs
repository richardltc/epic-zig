use dirs;
use std::fs::{self, File};
use std::path::Path;
use std::path::PathBuf;

use crate::types::{Hardware, PpCompute, ProgPowError, H256};
use progpow_cpu::cache::{NodeCacheBuilder, OptimizeFor};
use progpow_cpu::compute::{light_compute, PoW};

const CACHE_DIR: &str = "cache";
const EPIC_HOME: &str = ".epic";

fn get_cache_path() -> Result<PathBuf, ::std::io::Error> {
	// Check if epic dir exists
	let mut epic_path = match dirs::home_dir() {
		Some(p) => p,
		None => PathBuf::new(),
	};

	epic_path.push(EPIC_HOME);
	epic_path.push("main");
	epic_path.push(CACHE_DIR);
	// Create if the default path doesn't exist
	if !epic_path.exists() {
		fs::create_dir_all(epic_path.clone())?;
	}
	Ok(epic_path)
}

pub struct PpCPU {
	cache_builder: NodeCacheBuilder,
}

impl PpCPU {
	pub fn new() -> Self {
		PpCPU {
			cache_builder: NodeCacheBuilder::new(None),
		}
	}
}

impl PpCompute for PpCPU {
	fn init(&mut self) -> Result<(), ProgPowError> {
		Ok(())
	}

	fn verify(
		&self,
		header_hash: &H256,
		height: u64,
		nonce: u64,
	) -> Result<([u32; 8], [u32; 8]), ProgPowError> {
		let path_cache: PathBuf = get_cache_path().unwrap();

		let light = match self.cache_builder.light_from_file(&path_cache, height) {
			Ok(l) => l,
			Err(e) => {
				let mut light = self.cache_builder.light(&path_cache, height);
				if let Err(e) = light.to_file() {
					println!("Light cache file write error: {}", e);
				}
				light
			}
		};

		Ok(light.compute(&header_hash, nonce, height))
	}

	fn compute(&self, header: [u8; 32], height: u64, epoch: i32, boundary: u64) {
		unimplemented!()
	}

	fn hardware(&self) -> Hardware {
		Hardware::CPU
	}
}
