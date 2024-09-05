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
cls
color 0B
cd Tools
set /p answer="Do you want to tourney unban? (y/n): "

if /i "%answer%"=="y" (
    echo Proceeding with the action.
) else (
cls

exit
)
cls
color e
echo you will still need to temp spoof / perm spoof.
echo its recommended to create a restore point before continuing.


set /p answer="Do you want to continue? (y/n): "

if /i "%answer%"=="y" (
cls
color 4
echo the program is about to open and it will ask if you want to continue, type Y and wait for your pc to restart.
echo you will be logged out of your pc, do not restart or login to your pc until it has restarted.
echo Click Enter To Start.
pause >nul
timeout /t 2 /nobreak >nul
start sexytourneymoment.bat
timeout /t 6 /nobreak >nul
exit
) 
) else (
cls
)