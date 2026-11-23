@echo off
REM Builds NetScout for Windows from the Python source. Run this ONCE on a Windows machine that HAS Python.
REM The results in dist\ do NOT need Python on any machine you copy them to afterwards - and this script
REM now PROVES that before it finishes, by starting the built program with Python hidden from it.
setlocal
cd /d "%~dp0"

echo ============================================================
echo  NetScout - Windows Build
echo ============================================================
echo.
echo This step needs Python only on THIS machine, right now, to build the program.
echo The finished NetScout.exe will NOT need Python on the machines it is copied to.
echo.

REM ---- 1. Find a working Python ------------------------------------------------------------------
REM "py" launcher first (installed by the python.org installer even when "Add to PATH" was unticked),
REM then python / python3. Checked quietly with --version so Windows' Microsoft-Store stub can't pop up.
set PY=
py -3 --version >nul 2>&1
if not errorlevel 1 set PY=py -3
if not defined PY (
    python --version >nul 2>&1
    if not errorlevel 1 set PY=python
)
if not defined PY (
    python3 --version >nul 2>&1
    if not errorlevel 1 set PY=python3
)
if not defined PY goto :nopython

echo Using Python:
%PY% --version
echo.

REM ---- 2. Refuse the Microsoft Store version of Python -------------------------------------------
REM This is the #1 cause of "the .exe still needs Python on some PCs". The Store Python lives in a
REM sandboxed WindowsApps folder, and PyInstaller often cannot copy its Tcl/Tk (the window/graphics
REM library) into the build. The .exe then only opens on machines that happen to have Python installed.
%PY% -c "import sys; sys.exit(1 if 'WindowsApps' in sys.executable else 0)" >nul 2>&1
if errorlevel 1 goto :storepython

REM ---- 3. Make sure THIS Python has a working Tcl/Tk ---------------------------------------------
REM If tkinter is broken or missing here, there is nothing for PyInstaller to pack, and the .exe would
REM only work where someone else's Python supplies it. Stop now with a clear fix instead.
%PY% -c "import tkinter; tkinter.Tcl().eval('info patchlevel')" >nul 2>&1
if errorlevel 1 goto :notk

REM ---- 4. Warnings that decide WHICH PCs the result can run on -----------------------------------
%PY% -c "import sys; sys.exit(0 if 'free-threading' in sys.version else 1)" >nul 2>&1
if not errorlevel 1 (
    echo NOTE: This is the experimental "free-threaded" Python build. Bluetooth support will likely
    echo be skipped below. For a full build use a standard Python 3.11 / 3.12 / 3.13 from python.org.
    echo.
)
for /f %%B in ('%PY% -c "import struct; print(struct.calcsize('P')*8)"') do set PYBITS=%%B
for /f %%M in ('%PY% -c "import platform; print(platform.machine())"') do set PYARCH=%%M
echo Python is %PYBITS%-bit, %PYARCH%.
if "%PYBITS%"=="64" (
    echo   - The built program runs on 64-bit Windows 10/11 ^(nearly every PC and laptop today^).
    echo   - It will NOT run on old 32-bit Windows. For those, build again with 32-bit Python.
)
if /i "%PYARCH%"=="ARM64" (
    echo   - WARNING: this is ARM64 Python ^(e.g. a Snapdragon laptop^). The result will only run on
    echo     ARM64 PCs. Build on a normal Intel/AMD PC instead - that version runs on both.
)
echo.

REM ---- 5. Tools ----------------------------------------------------------------------------------
echo Installing/upgrading PyInstaller (required, one-time, needs internet)...
%PY% -m pip install --upgrade --only-binary=:all: pyinstaller pyinstaller-hooks-contrib
if errorlevel 1 (
    echo.
    echo ERROR: Could not install PyInstaller - see the messages above for why.
    pause
    exit /b 1
)
echo.
echo Installing bleak (optional - adds Bluetooth scanning to the built app)...
REM --only-binary: never try to COMPILE bleak's Windows "winrt" parts from source (needs a full MSVC
REM toolchain and can die in an internal compiler crash). Not fatal: without bleak, everything except
REM Bluetooth still works and the app says so.
%PY% -m pip install --upgrade --only-binary=:all: bleak
if errorlevel 1 (
    echo.
    echo WARNING: Could not install bleak - continuing WITHOUT Bluetooth support in this build.
    echo.
)
echo Installing Pillow (optional - shows the live picture in IP CAMERA)...
REM Not fatal either: without it, IP CAMERA still logs in and steers the camera, just without the picture.
%PY% -m pip install --upgrade --only-binary=:all: Pillow
if errorlevel 1 (
    echo.
    echo WARNING: Could not install Pillow - IP CAMERA will steer cameras but show no picture in this build.
    echo.
)

REM ---- 6. Clean old results, so nobody copies a stale or half-built program ------------------------
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

REM ---- 7. Build: single-file version ----------------------------------------------------------------
echo.
echo Building NetScout.exe (single file) ...
set NETSCOUT_ONEDIR=
%PY% -m PyInstaller --noconfirm --clean --workpath build\onefile netscout.spec
if errorlevel 1 goto :buildfail
if not exist "dist\NetScout.exe" goto :buildfail

REM ---- 8. Build: folder version (for PCs whose antivirus blocks the single file) ------------------
echo.
echo Building the folder version (NetScout-Folder) ...
set NETSCOUT_ONEDIR=1
%PY% -m PyInstaller --noconfirm --workpath build\onedir netscout.spec
set BUILD2=%errorlevel%
set NETSCOUT_ONEDIR=
if not "%BUILD2%"=="0" (
    echo WARNING: the folder version failed to build - the single-file version is still fine.
)

REM build\ holds half-finished intermediate files - including a NetScout.exe that does NOT work on its
REM own. Delete it so it can never be copied around by mistake.
if exist build rmdir /s /q build

REM ---- 9. PROVE it runs without Python ------------------------------------------------------------
REM Start the built program with Python removed from PATH and every Python/Tcl variable cleared, so it
REM cannot borrow anything from this machine's Python install. --selftest opens and closes a hidden
REM window and exits with code 0 if everything it needs is really packed inside.
echo.
echo Checking that the built program runs WITHOUT Python ...
call :selftest "dist\NetScout.exe"
if errorlevel 1 goto :selftestfail
echo   OK - dist\NetScout.exe starts on its own.
if exist "dist\NetScout-Folder\NetScout.exe" (
    call :selftest "dist\NetScout-Folder\NetScout.exe"
    if errorlevel 1 (
        echo   WARNING: the folder version failed the check - do not hand that one out.
    ) else (
        echo   OK - dist\NetScout-Folder\NetScout.exe starts on its own.
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Force -Path 'dist\NetScout-Folder' -DestinationPath 'dist\NetScout-Folder.zip'" >nul 2>&1
        if exist "dist\NetScout-Folder.zip" echo   Packed as dist\NetScout-Folder.zip for easy copying.
    )
)

REM ---- 9b. Build the one-click installer (if Inno Setup is installed) ----------------------------
REM This wraps the FAST folder build into dist\NetScout-Setup.exe - a friendly wizard with your logo,
REM Start-Menu/Desktop shortcuts and an uninstaller, that needs no admin rights. Optional: if Inno Setup
REM isn't installed, the loose .exe and the folder .zip above are still perfectly good to hand out.
echo.
echo Building the one-click installer (NetScout-Setup.exe) ...
set "ISCC="
where iscc >nul 2>&1 && set "ISCC=iscc"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC (
    echo   Inno Setup not found - skipping the installer. The .exe and folder .zip above are ready to hand out.
    echo   For the nice one-click installer, install Inno Setup 6 ^(free^): https://jrsoftware.org/isdl.php
    echo   then run this script again.
) else (
    if not exist "dist\NetScout-Folder\NetScout.exe" (
        echo   WARNING: the folder build is missing, so the installer cannot be built from it.
    ) else (
        "%ISCC%" /Qp netscout.iss
        if errorlevel 1 (
            echo   WARNING: the installer failed to compile - see the messages above.
        ) else (
            if exist "dist\NetScout-Setup.exe" echo   OK - dist\NetScout-Setup.exe built.
        )
    )
)

REM ---- 10. Desktop shortcut ----------------------------------------------------------------------
echo.
echo Creating a Desktop shortcut...
set "NS_EXE=%~dp0dist\NetScout.exe"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$s = (New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Desktop') + '\NetScout.lnk'); $s.TargetPath = '%NS_EXE%'; $s.WorkingDirectory = '%~dp0dist'; $s.IconLocation = '%NS_EXE%,0'; $s.Save()"
if errorlevel 1 (
    echo WARNING: Could not create the Desktop shortcut automatically.
    echo Right-click dist\NetScout.exe -^> Send to -^> Desktop ^(create shortcut^) instead.
) else (
    echo Desktop shortcut created: NetScout
)

echo.
echo ============================================================
echo  DONE - and verified to run without Python.
echo.
echo  HAND OUT ONE OF THESE (from the dist folder only):
echo    NetScout-Setup.exe    - BEST: the one-click installer (if Inno Setup was
echo                            installed). Branded wizard, shortcuts, uninstaller,
echo                            no admin needed. This is the one to put on GitHub.
echo    NetScout.exe          - one loose file, simplest. Copy it anywhere.
echo    NetScout-Folder.zip   - use this on PCs where the single file
echo                            won't open (strict antivirus/company PCs):
echo                            unzip, then run NetScout.exe inside.
echo.
echo  NEVER hand out the .py files - those DO need Python.
echo.
echo  First run on a new PC: Windows SmartScreen may say "unknown app".
echo  Click "More info", then "Run anyway".
echo ============================================================
pause
exit /b 0


REM ======================== helpers / error exits ========================

:selftest
setlocal
set "PATH=%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0"
set PYTHONHOME=
set PYTHONPATH=
set PYTHONSTARTUP=
set TCL_LIBRARY=
set TK_LIBRARY=
start "" /wait %1 --selftest
set RC=%errorlevel%
endlocal & exit /b %RC%

:nopython
echo ERROR: No working Python installation was found on this machine.
echo.
echo Download Python from https://www.python.org/downloads/windows/
echo On the first installer screen tick "Add python.exe to PATH", then install normally.
echo.
echo If Python IS installed but Windows opens the Microsoft Store instead:
echo   Settings - Apps - Advanced app settings - App execution aliases, and turn OFF
echo   "python.exe" and "python3.exe".
echo.
echo Run this script again afterwards.
pause
exit /b 1

:storepython
echo ERROR: This is the Microsoft Store version of Python.
echo.
echo Programs built with it often only open on PCs that ALSO have Python installed - the exact
echo "it still needs Python on some laptops" problem - because its Tcl/Tk cannot be packed properly.
echo.
echo Fix: install Python from https://www.python.org/downloads/windows/
echo      (tick "Add python.exe to PATH" and keep "tcl/tk and IDLE" ticked), then run this again.
echo      You can uninstall the Store version afterwards, or leave it - this script prefers python.org.
pause
exit /b 1

:notk
echo ERROR: This Python has no working Tcl/Tk (the library that draws NetScout's window).
echo.
echo Fix: run the python.org installer again, choose "Modify", make sure "tcl/tk and IDLE" is
echo      ticked, finish, then run this script again.
echo      Download: https://www.python.org/downloads/windows/
pause
exit /b 1

:buildfail
echo.
echo ERROR: The build failed - see the messages above for why.
pause
exit /b 1

:selftestfail
echo.
echo ERROR: The built NetScout.exe did NOT start without Python.
echo        Do not hand this copy out - it would fail on PCs without Python.
echo.
echo Most common reasons and fixes:
echo   - Python came from the Microsoft Store, or from Anaconda/conda: install python.org Python.
echo   - Antivirus quarantined part of the build: check its quarantine, then build again.
echo   - Run this script once more after a restart (a locked file can break the build).
echo To see the exact error: set console=True in netscout.spec, build again, and run
echo dist\NetScout.exe from a Command Prompt - the reason is printed there.
pause
exit /b 1
