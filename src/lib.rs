use pyo3::prelude::*;
use std::sync::OnceLock;

mod ciphers;
mod kdf;

pub fn get_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();

    VERSION.get_or_init(|| {
        let version = env!("CARGO_PKG_VERSION");
        version.replace("-alpha", "a").replace("-beta", "b")
    })
}

#[pymodule]
fn _crypto(_py: Python, module: &Bound<PyModule>) -> PyResult<()> {
    module.add("__version__", get_version())?;
    ciphers::init_pymodule(module)?;
    kdf::init_pymodule(module)?;

    Ok(())
}
