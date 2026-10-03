@echo off
setlocal
cd /d "%~dp0"
py -m pip install -r requirements.txt
py -m pip install pyinstaller
pyinstaller --clean --noconfirm packaging\PRISM.spec
copy /Y .env.example dist\.env >nul
if exist dist\.env.example del dist\.env.example
 echo.
 echo PRISM Windows build created in dist\PRISM.exe
endlocal
