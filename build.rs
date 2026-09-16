//! 嵌入 comctl32 v6 manifest(现代视觉样式)与版本信息
fn main() {
    // winres 不可用(缺 SDK 工具链)时静默跳过,不影响功能
    let res = winres::WindowsResource::new();
    #[cfg(windows)]
    {
        let mut res = res;
        res.set_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="HzxyCampusAuth" type="win32"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#,
        );
        if let Err(e) = res.compile() {
            println!("cargo:warning=manifest embed skipped: {e}");
        }
    }
    let _ = res;
}
