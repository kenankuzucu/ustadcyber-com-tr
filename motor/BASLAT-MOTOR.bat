@echo off
chcp 65001 >nul
title ÜSTAD KENAN - SİBER GÜVENLİK 3D MERKEZ · YEREL TARAMA MOTORU
color 0A
cls
echo.
echo   ██╗   ██╗███████╗████████╗ █████╗ ██████╗    ███╗   ███╗ ██████╗ ████████╗ ██████╗ ██████╗
echo   ██║   ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗   ████╗ ████║██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗
echo   ██║   ██║███████╗   ██║   ███████║██║  ██║   ██╔████╔██║██║   ██║   ██║   ██║   ██║██████╔╝
echo   ██║   ██║╚════██║   ██║   ██╔══██║██║  ██║   ██║╚██╔╝██║██║   ██║   ██║   ██║   ██║██╔══██╗
echo   ╚██████╔╝███████║   ██║   ██║  ██║██████╔╝   ██║ ╚═╝ ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║
echo    ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝    ╚═╝     ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝
echo.
echo   GERCEK TARAMA MOTORU  ·  v1.0  ·  yalnizca kendi cihazin icin
echo   ------------------------------------------------------------------
echo.

set PY=
where python >nul 2>nul && set PY=python
if "%PY%"=="" ( where py >nul 2>nul && set PY=py )
if "%PY%"=="" ( where python3 >nul 2>nul && set PY=python3 )

if "%PY%"=="" (
  echo   [HATA] Python bulunamadi!
  echo   Python kurulu degilse: https://www.python.org/downloads/  adresinden kurarken
  echo   "Add python.exe to PATH" kutusunu isaretle.
  echo.
  pause
  exit /b 1
)

echo   Python: %PY%
echo   Motor baslatiliyor... (bu pencereyi KAPATMA)
echo.
"%PY%" "%~dp0engine.py"
echo.
echo   Motor durdu. Kapatmak icin bir tusa bas.
pause
