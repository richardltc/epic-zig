pub type H256 = [u8; 32];

#[derive(Debug)]
pub enum Hardware {
	CPU,
	GPU,
}

#[derive(Debug)]
pub enum ProgPowError {
	NO_INITIALIZED,
	DAG,
	CACHE,
}

pub trait PpCompute: Sized {
	fn init(&mut self) -> Result<(), ProgPowError>;
	fn hardware(&self) -> Hardware;
	fn verify(
		&self,
		header_hash: &H256,
		height: u64,
		nonce: u64,
	) -> Result<([u32; 8], [u32; 8]), ProgPowError>;
	fn compute(&self, header: [u8; 32], height: u64, epoch: i32, target: u64);
}
