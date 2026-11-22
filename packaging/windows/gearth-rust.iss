; Inno Setup script for G-Earth Rust (Windows x64)
; Build with: iscc /DAppVersion=0.1.0 /DBinPath=..\target\release\gearth-desktop.exe packaging\windows\gearth-rust.iss

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef BinPath
  #define BinPath "..\..\target\release\gearth-desktop.exe"
#endif

[Setup]
AppId={{8D6B4F43-2C1B-4F4A-9B0D-73A62E19B5A1}
AppName=G-Earth Rust
AppVersion={#AppVersion}
AppPublisher=Tear1338
AppPublisherURL=https://github.com/Tear1338/G-Earth-Rust
DefaultDirName={autopf}\G-Earth Rust
DefaultGroupName=G-Earth Rust
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\dist
OutputBaseFilename=G-Earth-Rust-Setup-{#AppVersion}-x64
SetupIconFile=..\..\resources\g_earth_icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#BinPath}"; DestDir: "{app}"; DestName: "gearth-desktop.exe"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE-APACHE-MAVEN"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\NOTICE-APACHE-MAVEN"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\resources\UNICODE-LICENSE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\G-Earth Rust"; Filename: "{app}\gearth-desktop.exe"
Name: "{autodesktop}\G-Earth Rust"; Filename: "{app}\gearth-desktop.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\gearth-desktop.exe"; Description: "{cm:LaunchProgram,G-Earth Rust}"; Flags: nowait postinstall skipifsilent
