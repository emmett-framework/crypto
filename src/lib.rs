use pyo3::prelude::*;

mod ciphers;
mod kdf;

#[pymodule]
fn _crypto(_py: Python, module: &PyModule) -> PyResult<()> {
    ciphers::init_pymodule(module)?;
    kdf::init_pymodule(module)?;

    Ok(())
}
