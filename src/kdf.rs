use std::num::NonZeroU32;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ring::pbkdf2 as _pbkdf2;

fn pbkdf2(py: Python, data: &[u8], salt: &[u8], rounds: u32, klen: u32, hash_algo: _pbkdf2::Algorithm) -> Py<PyBytes> {
    let mut vdata = vec![0u8; klen as usize];
    let wdata: &mut [u8] = &mut vdata;
    _pbkdf2::derive(hash_algo, NonZeroU32::new(rounds).unwrap(), salt, data, wdata);
    PyBytes::new(py, wdata).into()
}

#[pyfunction]
#[pyo3(signature = (data, salt, rounds, klen))]
fn pbkdf2_sha1(py: Python, data: &[u8], salt: &[u8], rounds: u32, klen: u32) -> PyResult<Py<PyBytes>> {
    Ok(pbkdf2(py, data, salt, rounds, klen, _pbkdf2::PBKDF2_HMAC_SHA1))
}

#[pyfunction]
#[pyo3(signature = (data, salt, rounds, klen))]
fn pbkdf2_sha256(py: Python, data: &[u8], salt: &[u8], rounds: u32, klen: u32) -> PyResult<Py<PyBytes>> {
    Ok(pbkdf2(py, data, salt, rounds, klen, _pbkdf2::PBKDF2_HMAC_SHA256))
}

#[pyfunction]
#[pyo3(signature = (data, salt, rounds, klen))]
fn pbkdf2_sha384(py: Python, data: &[u8], salt: &[u8], rounds: u32, klen: u32) -> PyResult<Py<PyBytes>> {
    Ok(pbkdf2(py, data, salt, rounds, klen, _pbkdf2::PBKDF2_HMAC_SHA384))
}

#[pyfunction]
#[pyo3(signature = (data, salt, rounds, klen))]
fn pbkdf2_sha512(py: Python, data: &[u8], salt: &[u8], rounds: u32, klen: u32) -> PyResult<Py<PyBytes>> {
    Ok(pbkdf2(py, data, salt, rounds, klen, _pbkdf2::PBKDF2_HMAC_SHA512))
}

pub(crate) fn init_pymodule(module: &PyModule) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(pbkdf2_sha1, module)?)?;
    module.add_function(wrap_pyfunction!(pbkdf2_sha256, module)?)?;
    module.add_function(wrap_pyfunction!(pbkdf2_sha384, module)?)?;
    module.add_function(wrap_pyfunction!(pbkdf2_sha512, module)?)?;

    Ok(())
}
