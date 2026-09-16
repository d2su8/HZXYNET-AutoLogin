//! DPAPI 加密存储(Windows 数据保护 API,绑定当前用户,Chrome/Edge 同款凭据保护机制)

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// 应用熵: 提高其他程序解密难度(仍绑定当前用户)
const ENTROPY: &[u8] = b"HzxyCampusAuth::v1::dpapi-entropy";

fn blob_from(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    }
}

/// 加密字符串 -> base64(DPAPI blob)
pub fn protect(plain: &str) -> Result<String, String> {
    unsafe {
        let plain_utf16: Vec<u16> = plain.encode_utf16().chain([0]).collect();
        let data_in = blob_from(bytemuck_u16(&plain_utf16));
        let entropy = blob_from(ENTROPY);
        let mut data_out: CRYPT_INTEGER_BLOB = std::mem::zeroed();
        let ok = CryptProtectData(
            &data_in,
            std::ptr::null(),
            &entropy,
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        );
        if ok == 0 {
            return Err("CryptProtectData 失败".into());
        }
        let slice =
            std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();
        LocalFree(data_out.pbData as HLOCAL);
        Ok(B64.encode(slice))
    }
}

/// base64(DPAPI blob) -> 解密字符串
pub fn unprotect(b64: &str) -> Result<String, String> {
    let bytes = B64
        .decode(b64)
        .map_err(|e| format!("base64 解码失败: {e}"))?;
    unsafe {
        let data_in = blob_from(&bytes);
        let entropy = blob_from(ENTROPY);
        let mut data_out: CRYPT_INTEGER_BLOB = std::mem::zeroed();
        let ok = CryptUnprotectData(
            &data_in,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        );
        if ok == 0 {
            return Err("CryptUnprotectData 失败(可能换了 Windows 用户或系统)".into());
        }
        // DPAPI 输出是 UTF-16 字符串
        let utf16: Vec<u16> = std::slice::from_raw_parts(
            data_out.pbData as *const u16,
            data_out.cbData as usize / 2,
        )
        .to_vec();
        LocalFree(data_out.pbData as HLOCAL);
        let len = utf16.iter().position(|&c| c == 0).unwrap_or(utf16.len());
        Ok(String::from_utf16_lossy(&utf16[..len]))
    }
}

/// u16 切片按小端字节序转 u8 切片
fn bytemuck_u16(v: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let enc = protect("hello密码123").unwrap();
        assert!(!enc.contains("hello"));
        assert_eq!(unprotect(&enc).unwrap(), "hello密码123");
    }
}
