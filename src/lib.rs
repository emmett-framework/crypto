#[cfg(not(all(target_os="linux", target_arch="aarch64")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use pyo3::prelude::*;

mod ciphers;
mod kdf;


#[pymodule]
fn _crypto(_py: Python, module: &PyModule) -> PyResult<()> {
    ciphers::init_pymodule(module)?;
    kdf::init_pymodule(module)?;

    Ok(())
}
