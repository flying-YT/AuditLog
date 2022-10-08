@echo off
echo ------------------------
echo   AuditLog Reprint
echo ------------------------
echo Please input YYYYMMDD (output date)

set /p INPUTSTR=""

cls

powershell -NoProfile -ExecutionPolicy Unrestricted .\AuditLog.ps1 %INPUTSTR%