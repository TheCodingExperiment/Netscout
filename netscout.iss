; ============================================================================
;  NetScout - Windows installer (Inno Setup 6)
;  Build it with Inno Setup's compiler:   iscc netscout.iss
;  build_windows.bat does this for you automatically if Inno Setup is installed.
;
;  Produces:  dist\NetScout-Setup.exe  - a single, friendly installer that:
;    - needs NO admin rights (installs just for the current user, so no UAC prompt)
;    - installs the FAST "folder" build (starts instantly - never unpacks to %TEMP%)
;    - adds Start Menu + optional Desktop shortcuts with your reaper icon
;    - shows your license, and registers a proper uninstaller
;  Get Inno Setup (free): https://jrsoftware.org/isdl.php
; ============================================================================

#define AppName "NetScout"
#define AppVersion "1.5.0"
#define AppPublisher "TheCodingExperiment"
#define AppExe "NetScout.exe"

[Setup]
; A fixed AppId keeps upgrades and the uninstaller matched across versions - do not change it.
AppId={{8F3C2A14-6B7E-4D59-9E2A-1C0DE5CA0001}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=NetScout network scanner installer
VersionInfoCopyright=Copyright (C) 2026 {#AppPublisher}. All rights reserved.

; --- install for the current user only: no administrator rights, no UAC prompt ---
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes

; --- where the finished installer is written, and what it's called ---
OutputDir=dist
OutputBaseFilename=NetScout-Setup
Compression=lzma2/max
SolidCompression=yes

; --- branding: your reaper logo throughout the wizard ---
SetupIconFile=netscout.ico
WizardStyle=modern
WizardImageFile=installer\wizard_large.bmp
WizardSmallImageFile=installer\wizard_small.bmp
WizardImageStretch=no
DisableWelcomePage=no

; --- show the license the user agreed to ---
LicenseFile=LICENSE

UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "quicklaunchicon"; Description: "Create a &Quick Launch shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
; Ship the WHOLE folder build (fast start, antivirus-friendly - nothing unpacks at launch).
; build_windows.bat produces dist\NetScout-Folder before this installer is compiled.
Source: "dist\NetScout-Folder\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
; Keep the license alongside the app so it travels with every install.
Source: "LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: quicklaunchicon

[Run]
; Offer to launch NetScout right after a successful install.
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Leave the user's saved settings (~/.netscout_*) alone - those are their data, not ours to delete.
Type: dirifempty; Name: "{app}"
