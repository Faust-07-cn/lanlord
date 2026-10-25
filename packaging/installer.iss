; Inno Setup script for lanmgr desktop installer (production phase).
; Build: iscc packaging\installer.iss   (requires Inno Setup 6)
; Produces a setup.exe that installs the Windows service + web UI.

#define MyAppName "lanmgr - 局域网管理系统"
#define MyAppVersion "0.1.0"
#define MyAppExeName "lanmgr.exe"

[Setup]
AppId={{8A9C1F2E-4B3D-4E5A-9C6F-3D2E1B0A9C8D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\lanmgr
DefaultGroupName=lanmgr
DisableProgramGroupPage=yes
OutputDir=..\build\installer
OutputBaseFilename=lanmgr-setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\build\lanmgr.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\web\*"; DestDir: "{app}\web"; Flags: ignoreversion recursesubdirs

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--service-install"; Flags: runhidden; StatusMsg: "注册系统服务…"

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--service-uninstall"; Flags: runhidden

[Icons]
Name: "{group}\lanmgr 控制台"; Filename: "http://127.0.0.1:8686/"
Name: "{autoprograms}\lanmgr"; Filename: "http://127.0.0.1:8686/"
