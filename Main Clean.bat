@echo off
REM --> Check for permissions
"%SYSTEMROOT%\system32\icacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting Admin...
    goto UACPrompt
) else (
    goto gotAdmin
)

:UACPrompt
setlocal DisabledelayedExpansion
set "batchPath=%~f0"
setlocal EnabledelayedExpansion
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "cmd.exe", "/c ""!batchPath!"" %*", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
exit /B

:gotAdmin
pushd "%CD%"
CD /D "%~dp0"
color 0B
cd Tools
title uwu cleaner .gg/disk
cls
echo Click enter to clean your dirty ass pc uwu...
pause

REM Get current user's profile directory
set "UserProfileDir=%UserProfile%"
REM Assuming Fortnite is installed in the default location
set "FortniteDir=%ProgramFiles%\Epic Games\Fortnite"
set "TempDir=%UserProfileDir%\AppData\Local\Temp"
set "LogFile=%SystemDrive%\$LogFile"
set "IoStoreOnDemandIni=%FortniteDir%\Cloud\IoStoreOnDemand.ini"
set "CloudContentJson=%FortniteDir%\Cloud\cloudcontent.json"
set "SavedDir=%UserProfileDir%\AppData\Local\FortniteGame\Saved"
set "UnrealEngineDir=%UserProfileDir%\AppData\Local\UnrealEngine"

REM Delete and recreate Temp directory
rmdir /s /q "%TempDir%"
mkdir "%TempDir%"

REM Recreate $LogFile
del "%LogFile%"
echo. > "%LogFile%"

REM Delete and recreate IoStoreOnDemand.ini in Fortnite directory
del "%IoStoreOnDemandIni%"
echo. > "%IoStoreOnDemandIni%"

REM Delete and recreate cloudcontent.json in Fortnite directory
del "%CloudContentJson%"
echo. > "%CloudContentJson%"

REM Delete and recreate Saved directory in FortniteGame directory
rmdir /s /q "%SavedDir%"
mkdir "%SavedDir%"

REM Delete and recreate UnrealEngine directory in Local directory
rmdir /s /q "%UnrealEngineDir%"
mkdir "%UnrealEngineDir%"

@echo off
:: Check for administrator privileges
NET SESSION >nul 2>nul
if %errorlevel% neq 0 (
    echo Administrator privileges required. Please run this script as an administrator.
    pause
    exit /b
)

echo y|net stop bits
echo y|net stop wuauserv
echo y|net stop msiserver
echo y|net stop cryptsvc
echo y|net stop appidsvc

sc qc XblAuthManager | findstr "STATE" | findstr "RUNNING" && sc stop XblAuthManager
sc qc XblGameSave | findstr "STATE" | findstr "RUNNING" && sc stop XblGameSave
sc qc XboxNetApiSvc | findstr "STATE" | findstr "RUNNING" && sc stop XboxNetApiSvc
sc qc XboxGipSvc | findstr "STATE" | findstr "RUNNING" && sc stop XboxGipSvc
sc qc xbgm | findstr "STATE" | findstr "RUNNING" && sc stop xbgm

net start bits
net start wuauserv
net start msiserver
net start cryptsvc
net start appidsvc

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f

powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -changename 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c "Big Performance"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" /v "BoostState" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" /v "BoostValue" /t REG_DWORD /d 0x3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v Attributes /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v Attributes /t REG_DWORD /d 2 /f
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg -change -disk-timeout-ac 20
powercfg -change -disk-timeout-dc 1
powercfg -change -standby-timeout-ac 60
powercfg -change -standby-timeout-dc 30
powercfg -change -monitor-timeout-ac 45
powercfg -change -monitor-timeout-dc 30

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\%SID%\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9032078010000000 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 3 /f

del /s /f /q %appdata%\Microsoft\Teams\*.* 2> nul
rmdir /s /q %appdata%\Microsoft\Teams 2> nul
del /s /f /q %localappdata%\Microsoft\Outlook\RoamCache*.* 2> nul
rmdir /s /q %localappdata%\Microsoft\Outlook\RoamCache 2> nul

"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" /update user

reg add "HKEY_USERS\%SID%\Control Panel\Keyboard" /v "PrintScreenKeyForSnippingEnabled" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 2048 /t REG_DWORD /d 7 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 04 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 08 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 256 /t REG_DWORD /d 0x3c /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 32 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 512 /t REG_DWORD /d 60 /f
reg add "HKEY_USERS\%SID%\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 1024 /t REG_DWORD /d 1 /f

del /s /f /q c:\windows\temp\*.* 2> nul
rd /s /q c:\windows\temp 2> nul
md c:\windows\temp 2> nul
del /s /f /q C:\WINDOWS\Prefetch 2> nul
del /s /f /q %temp%\*.* 2> nul
rd /s /q %temp% 2> nul
md %temp% 2> nul
rd /s /q c:\windows\tempor~1 2> nul
del /f /q c:\windows\tempor~1 2> nul
del /f /q c:\windows\temp 2> nul
rd /s /q c:\windows\tmp 2> nul
del /f /q c:\windows\tmp 2> nul
rd /s /q c:\windows\ff*.tmp 2> nul
del /f /q c:\windows\ff*.tmp 2> nul
rd /s /q c:\windows\history 2> nul
del /f /q c:\windows\history 2> nul
rd /s /q c:\windows\cookies 2> nul
del /f /q c:\windows\cookies 2> nul
rd /s /q c:\windows\recent 2> nul

del C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCookies\ /f /s /q
del C:\Users\%username%\AppData\Local\Microsoft\Windows\History\ /f /s /q
del C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\ /f /s /q
del C:\Users\%username%\AppData\Local\Temp\ /f /s /q
del C:\Windows\Temp\ /f /s /q
del C:\Windows\Prefetch\ /f /s /q
del C:\Temp\ /f /s /q


del /f /q c:\windows\recent 2> nul
rd /s /q c:\windows\spool\printers 2> nul
del /f /q c:\windows\spool\printers 2> nul
del c:\WIN386.SWP 2> nul

del /s /q /f "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat"
del /s /q /f "%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat"

ren %SYSTEMROOT%\winsxs\pending.xml pending.xml.bak
ren %SYSTEMROOT%\SoftwareDistribution SoftwareDistribution.bak
ren %SYSTEMROOT%\SoftwareDistribution\DataStore DataStore.bak
ren %SYSTEMROOT%\SoftwareDistribution\Download Download.bak
ren %SYSTEMROOT%\System32\catroot2 catroot2.bak
ren %SYSTEMROOT%\WindowsUpdate.log WindowsUpdate.log.bak

sc.exe sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
sc.exe sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)

regsvr32.exe /s %windir%\system32\atl.dll
regsvr32.exe /s %windir%\system32\urlmon.dll
regsvr32.exe /s %windir%\system32\mshtml.dll
regsvr32.exe /s %windir%\system32\shdocvw.dll
regsvr32.exe /s %windir%\system32\browseui.dll
regsvr32.exe /s %windir%\system32\jscript.dll
regsvr32.exe /s %windir%\system32\vbscript.dll
regsvr32.exe /s %windir%\system32\scrrun.dll
regsvr32.exe /s %windir%\system32\msxml.dll
regsvr32.exe /s %windir%\system32\msxml3.dll
regsvr32.exe /s %windir%\system32\msxml6.dll
regsvr32.exe /s %windir%\system32\actxprxy.dll
regsvr32.exe /s %windir%\system32\softpub.dll
regsvr32.exe /s %windir%\system32\wintrust.dll
echo lol this is released by sas-sy if somebody skids this please shame them 
regsvr32.exe /s %windir%\system32\dssenh.dll
regsvr32.exe /s %windir%\system32\rsaenh.dll
regsvr32.exe /s %windir%\system32\gpkcsp.dll
regsvr32.exe /s %windir%\system32\sccbase.dll
regsvr32.exe /s %windir%\system32\slbcsp.dll
regsvr32.exe /s %windir%\system32\cryptdlg.dll
regsvr32.exe /s %windir%\system32\oleaut32.dll
regsvr32.exe /s %windir%\system32\ole32.dll
regsvr32.exe /s %windir%\system32\shell32.dll
regsvr32.exe /s %windir%\system32\initpki.dll
regsvr32.exe /s %windir%\system32\wuapi.dll
regsvr32.exe /s %windir%\system32\wuaueng.dll
regsvr32.exe /s %windir%\system32\wuaueng1.dll
regsvr32.exe /s %windir%\system32\wucltui.dll
regsvr32.exe /s %windir%\system32\wups.dll
regsvr32.exe /s %windir%\system32\wups2.dll
regsvr32.exe /s %windir%\system32\wuweb.dll
regsvr32.exe /s %windir%\system32\qmgr.dll
regsvr32.exe /s %windir%\system32\qmgrprxy.dll
regsvr32.exe /s %windir%\system32\wucltux.dll
regsvr32.exe /s %windir%\system32\muweb.dll
regsvr32.exe /s %windir%\system32\wuwebv.dll

echo n|gpupdate /force
rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN
wmic.exe /Namespace:\\root\default Path SystemRestore Call Enable "C:\"

net start bits
net start wuauserv
net start msiserver
net start cryptsvc
net start appidsvc




cls


echo Cleaning Needed Gpu/Registry...
echo source code in Tools/User
timeout /t 3 /nobreak >nul
cd Tools
start /min /wait nigga.bat
cls


echo Running a simple perm spoof...
echo its ok if your motherboard is not supported
timeout /t 3 /nobreak >nul

start /min /wait example.bat
cls
echo Cleaning FiveM...
timeout /t 3 /nobreak >nul

start /min /wait fivemclean.bat
cls

echo Repairing Wifi...
timeout /t 3 /nobreak >nul

start /min /wait fixasswifi.bat
cls
echo Spoofing mac...
timeout /t 3 /nobreak >nul

start /min /wait macspoof.bat
cls
echo Spoofing Volumes...
timeout /t 3 /nobreak >nul

start /min /wait volumeidspoof.bat
cls
echo Spoofing registry part 1...
timeout /t 3 /nobreak >nul

start /min /wait reg1.bat
cls
echo Spoofing registry part 2...
timeout /t 2 /nobreak >nul
echo The prompt will be shown for this one, if you see any questions asking yes/no always enter yes!...
timeout /t 2 /nobreak >nul
echo Click Enter to start...
pause >nul
start /wait reg2.bat
cls

echo Clearing 2024 eac traces... bboy 
timeout /t 2 /nobreak >nul
echo The prompt will be shown for this one, if you see any questions asking yes/no always enter yes!...
timeout /t 2 /nobreak >nul
echo Click Enter to start...
pause >nul
start /wait sassyssexycleaner.bat
cls




echo Clearing Deep Traces...
timeout /t 2 /nobreak >nul
echo This can take some time, if it takes longer then 5 minutes check the minimized command prompt on your task bar, it may need user input or there could be a error.
timeout /t 2 /nobreak >nul
start /min /wait deeptracefuck.bat
cls

color 2
 echo Your pc is now clean  ...
 echo also you need to restart your pc, 
pause
exit

