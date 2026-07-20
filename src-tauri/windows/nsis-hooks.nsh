!macro NSIS_HOOK_POSTINSTALL
  ExecWait '"$INSTDIR\dnsblackhole.exe" --windows-service-install-request --legacy-data-dir "$APPDATA\com.dnsblackhole.app"' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "DnsBlackhole DNS 系统服务安装失败（退出码 $0）。请确认已允许管理员权限后重试安装。"
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ExecWait '"$INSTDIR\dnsblackhole.exe" --windows-service-uninstall-request' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "DnsBlackhole DNS 系统服务卸载失败（退出码 $0）。为避免残留系统服务，应用卸载已取消。"
    Abort
  ${EndIf}
!macroend
