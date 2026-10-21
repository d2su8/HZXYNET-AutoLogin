//! campus-auth 共享引擎库：认证、网络、加密、存储、自助接口。
//!
//! GUI（`campus-auth.exe`）复用本库；各模块职责见对应文件头注释。

pub mod auth;
pub mod autostart;
pub mod common;
pub mod crypto;
pub mod net;
pub mod selfsvc;
pub mod store;
