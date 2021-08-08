use pyo3::prelude::*;

mod ciphers;
mod kdf;


#[pymodule]
fn emmett_crypto(py: Python, module: &PyModule) -> PyResult<()> {
    module.add_submodule(ciphers::build_pymodule(py)?)?;
    module.add_submodule(kdf::build_pymodule(py)?)?;

    Ok(())
}
