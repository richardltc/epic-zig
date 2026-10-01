pub mod cpu;

#[cfg(feature = "opencl")]
pub mod gpu;
#[cfg(feature = "cuda")]
pub mod gpu;

pub use self::cpu::PpCPU;

#[cfg(feature = "opencl")]
pub use self::gpu::PpGPU;
#[cfg(feature = "cuda")]
pub use self::gpu::PpGPU;
