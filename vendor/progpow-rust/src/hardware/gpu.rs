use crate::types::{Hardware, PpCompute, ProgPowError, H256};
use progpow_gpu::{Driver, GPU};

pub struct PpGPU {
	pub gpu: GPU,
}

impl PpGPU {
	pub fn new(device: u32, driver: u8) -> Self {
		let dr: Driver = Driver::from_u8(driver);
		PpGPU {
			gpu: GPU::new(device, dr),
		}
	}

	pub fn compute_with_startnonce(&self, header: [u8; 32], height: u64, epoch: i32, target: u64, start_nonce: u64) {
		self.gpu.compute(header, height, epoch, target, start_nonce);
	}

	pub fn get_solutions(&self) -> Option<(u64, [u8; 32])> {
		self.gpu.solutions().unwrap()
	}
}

impl PpCompute for PpGPU {
	fn init(&mut self) -> Result<(), ProgPowError> {
		self.gpu.init();
		Ok(())
	}

	fn verify(
		&self,
		header: &[u8; 32],
		height: u64,
		nonce: u64,
	) -> Result<([u32; 8], [u32; 8]), ProgPowError> {
		unimplemented!()
	}

	fn compute(&self, header: [u8; 32], height: u64, epoch: i32, target: u64) {
		self.gpu.compute(header, height, epoch, target, 0);
	}

	fn hardware(&self) -> Hardware {
		Hardware::GPU
	}
}
