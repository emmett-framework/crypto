use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ctr::cipher::{NewCipher, AsyncStreamCipher, StreamCipher};

type Aes128Cfb8 = cfb8::Cfb8<aes::Aes128>;
type Aes256Cfb8 = cfb8::Cfb8<aes::Aes256>;
type Aes128Cfb128 = cfb_mode::Cfb<aes::Aes128>;
type Aes256Cfb128 = cfb_mode::Cfb<aes::Aes256>;
type Aes128Ctr128 = ctr::Ctr128BE<aes::Aes128>;
type Aes256Ctr128 = ctr::Ctr128BE<aes::Aes256>;


fn aes_asyncstream_encrypt<C: AsyncStreamCipher>(py: Python, cipher: &mut C, data: &[u8]) -> Py<PyBytes> {
    let mut wdata: Vec<u8> = data.into();
    cipher.encrypt(&mut wdata);
    PyBytes::new(py, &wdata).into()
}

fn aes_asyncstream_decrypt<C: AsyncStreamCipher>(py: Python, cipher: &mut C, data: &[u8]) -> Py<PyBytes> {
    let mut wdata: Vec<u8> = data.into();
    cipher.decrypt(&mut wdata);
    PyBytes::new(py, &wdata).into()
}

fn aes_stream<C: StreamCipher>(py: Python, cipher: &mut C, data: &[u8]) -> Py<PyBytes> {
    let mut wdata: Vec<u8> = data.into();
    cipher.apply_keystream(&mut wdata);
    PyBytes::new(py, &wdata).into()
}

#[pyfunction]
fn aes128_cfb8_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes128Cfb8::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_encrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes128_cfb8_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes128Cfb8::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_decrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes256_cfb8_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes256Cfb8::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_encrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes256_cfb8_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes256Cfb8::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_decrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes128_cfb128_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes128Cfb128::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_encrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes128_cfb128_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes128Cfb128::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_decrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes256_cfb128_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes256Cfb128::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_encrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes256_cfb128_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes256Cfb128::new_from_slices(key.into(), nonce.into()).unwrap();
    Ok(aes_asyncstream_decrypt(py, &mut cipher, data))
}

#[pyfunction]
fn aes128_ctr128(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes128Ctr128::new(key.into(), nonce.into());
    Ok(aes_stream(py, &mut cipher, data))
}

#[pyfunction]
fn aes256_ctr128(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes256Ctr128::new(key.into(), nonce.into());
    Ok(aes_stream(py, &mut cipher, data))
}

pub(crate) fn build_pymodule(py: Python) -> PyResult<&PyModule> {
    let module = PyModule::new(py, "ciphers")?;

    module.add_function(wrap_pyfunction!(aes128_cfb8_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes128_cfb8_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes256_cfb8_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes256_cfb8_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes128_cfb128_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes128_cfb128_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes256_cfb128_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes256_cfb128_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes128_ctr128, module)?)?;
    module.add_function(wrap_pyfunction!(aes256_ctr128, module)?)?;

    Ok(module)
}
