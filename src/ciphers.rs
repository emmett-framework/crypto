use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ctr::cipher::{AsyncStreamCipher, BlockEncryptMut, BlockDecryptMut, KeyIvInit, StreamCipher};

type Aes128Cfb8Decryptor = cfb8::Decryptor<aes::Aes128>;
type Aes128Cfb8Encryptor = cfb8::Encryptor<aes::Aes128>;
type Aes256Cfb8Decryptor = cfb8::Decryptor<aes::Aes256>;
type Aes256Cfb8Encryptor = cfb8::Encryptor<aes::Aes256>;
type Aes128Cfb128Decryptor = cfb_mode::Decryptor<aes::Aes128>;
type Aes128Cfb128Encryptor = cfb_mode::Encryptor<aes::Aes128>;
type Aes256Cfb128Decryptor = cfb_mode::Decryptor<aes::Aes256>;
type Aes256Cfb128Encryptor = cfb_mode::Encryptor<aes::Aes256>;
type Aes128Ctr128 = ctr::Ctr128BE<aes::Aes128>;
type Aes256Ctr128 = ctr::Ctr128BE<aes::Aes256>;


fn aes_asyncstream_encrypt<C: AsyncStreamCipher + BlockEncryptMut>(py: Python, cipher: C, data: &[u8]) -> Py<PyBytes> {
    let mut wdata: Vec<u8> = data.into();
    cipher.encrypt(&mut wdata);
    PyBytes::new(py, &wdata).into()
}

fn aes_asyncstream_decrypt<C: AsyncStreamCipher + BlockDecryptMut>(py: Python, cipher: C, data: &[u8]) -> Py<PyBytes> {
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
#[pyo3(signature = (data, key, nonce))]
fn aes128_cfb8_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes128Cfb8Encryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_encrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes128_cfb8_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes128Cfb8Decryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_decrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes256_cfb8_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes256Cfb8Encryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_encrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes256_cfb8_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes256Cfb8Decryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_decrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes128_cfb128_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes128Cfb128Encryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_encrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes128_cfb128_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes128Cfb128Decryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_decrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes256_cfb128_encrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes256Cfb128Encryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_encrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes256_cfb128_decrypt(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let cipher = Aes256Cfb128Decryptor::new(key.into(), nonce.into());
    Ok(aes_asyncstream_decrypt(py, cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes128_ctr128(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes128Ctr128::new(key.into(), nonce.into());
    Ok(aes_stream(py, &mut cipher, data))
}

#[pyfunction]
#[pyo3(signature = (data, key, nonce))]
fn aes256_ctr128(py: Python, data: &[u8], key: &[u8], nonce: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut cipher = Aes256Ctr128::new(key.into(), nonce.into());
    Ok(aes_stream(py, &mut cipher, data))
}

pub(crate) fn init_pymodule(module: &PyModule) -> PyResult<()> {
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

    Ok(())
}
