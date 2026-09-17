# AI 辅助说明 (AI-NOTES)

本项目由 **AI 辅助完成**（AI-Assisted）。

- 代码、文档与界面由 AI 与人工协作完成：人工提出需求并进行多轮真实环境测试与验收，AI 负责协议实现、代码编写与问题修复。
- 认证协议为针对校园网 bossWeb 门户的实测逆向结果，详见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。
- 技术要点：GUI 为纯 Win32 API（windows-sys）原生实现；HTTP 客户端为手写实现（门户为明文 HTTP）；密码使用 Windows DPAPI 加密存储（绑定当前用户）。
- 本项目仅供个人学习交流使用，请勿用于商业化，请遵守所在学校/机构的网络使用规定；使用产生的一切后果由使用者自行承担。