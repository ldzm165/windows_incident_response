@echo off
REM Incident Response Evidence Collection Script
REM Author: Lenin Guerrero
REM Version: 2.0

:: ============================================
:: CONFIGURATION
:: ============================================
set EVIDENCE_DIR=C:\IR_Evidence_%COMPUTERNAME%_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%
set COLLECTION_LOG=%EVIDENCE_DIR%\collection_summary.txt

:: Create directory with timestamp
mkdir "%EVIDENCE_DIR%" 2>nul
if errorlevel 1 (
    echo ERROR: Failed to create primary evidence directory
    set EVIDENCE_DIR=%USERPROFILE%\Desktop\IR_Evidence_%COMPUTERNAME%_%date:~-4,4%%date:~-10,2%%date:~-7,2%
    mkdir "%EVIDENCE_DIR%"
)

:: ============================================
:: COLLECTION FUNCTIONS
:: ============================================

:: Function: Add section header to file
:AddHeader
echo. >> %~1
echo ============================================ >> %~1
echo %~2 >> %~1
echo ============================================ >> %~1
echo Collection Time: %date% %time% >> %~1
echo Computer: %COMPUTERNAME% >> %~1
echo. >> %~1
goto :EOF

:: Function: Execute and append with header
:CollectData
echo [%time%] Collecting: %~2 >> "%COLLECTION_LOG%"
call :AddHeader "%~1" "%~2"
%~3 >> "%~1" 2>&1
echo. >> "%~1"
goto :EOF

:: ============================================
:: INITIALIZE LOGS
:: ============================================
echo Incident Response Evidence Collection > "%COLLECTION_LOG%"
echo Started: %date% %time% >> "%COLLECTION_LOG%"
echo Target: %COMPUTERNAME% >> "%COLLECTION_LOG%"
echo Collector: %USERNAME% >> "%COLLECTION_LOG%"
echo ============================================ >> "%COLLECTION_LOG%"

:: ============================================
:: 1. SYSTEM INFORMATION (Single File)
:: ============================================
set SYS_INFO=%EVIDENCE_DIR%\01_System_Information.txt

call :CollectData "%SYS_INFO%" "Date and Time Collection Started" "echo Collection initiated at: %date% %time%"
call :CollectData "%SYS_INFO%" "WMIC OS Information" "wmic os get LocalDateTime,Version,Manufacturer,Name /value"
call :CollectData "%SYS_INFO%" "System Information" "systeminfo"
call :CollectData "%SYS_INFO%" "System Uptime" "net statistics server | find \"Statistics since\""
call :CollectData "%SYS_INFO%" "Time Zone" "systeminfo | find \"Time Zone\""

:: ============================================
:: 2. USER AND GROUP INFORMATION (Single File)
:: ============================================
set USER_INFO=%EVIDENCE_DIR%\02_User_and_Group_Information.txt

call :CollectData "%USER_INFO%" "Current User Context" "whoami /all"
call :CollectData "%USER_INFO%" "All User Accounts" "net user"
call :CollectData "%USER_INFO%" "Detailed User Accounts" "wmic useraccount get name,disabled,lockout,passwordchangeable"
call :CollectData "%USER_INFO%" "Local Groups" "net localgroup"
call :CollectData "%USER_INFO%" "Administrators Group (English)" "net localgroup administrators"
call :CollectData "%USER_INFO%" "Administrators Group (Spanish)" "net localgroup administradores"
call :CollectData "%USER_INFO%" "Remote Desktop Users" "net localgroup \"Remote Desktop Users\""
call :CollectData "%USER_INFO%" "Account Policies" "net accounts"
call :CollectData "%USER_INFO%" "Logged On Users" "qwinsta"

:: ============================================
:: 3. PROCESS AND SERVICE INFORMATION (Single File)
:: ============================================
set PROCESS_INFO=%EVIDENCE_DIR%\03_Process_and_Service_Information.txt

call :CollectData "%PROCESS_INFO%" "Running Processes with Services" "tasklist /svc"
call :CollectData "%PROCESS_INFO%" "Process Details with Command Lines" "wmic process get ProcessId,Name,CommandLine,ExecutablePath"
call :CollectData "%PROCESS_INFO%" "Loaded DLLs per Process" "tasklist /m"
call :CollectData "%PROCESS_INFO%" "Running Services" "net start"
call :CollectData "%PROCESS_INFO%" "Service Details" "sc query type= service state= all"
call :CollectData "%PROCESS_INFO%" "Service Configurations" "wmic service get name,displayname,startmode,pathname"

:: ============================================
:: 4. NETWORK INFORMATION (Single File)
:: ============================================
set NETWORK_INFO=%EVIDENCE_DIR%\04_Network_Configuration.txt

call :CollectData "%NETWORK_INFO%" "IP Configuration" "ipconfig /all"
call :CollectData "%NETWORK_INFO%" "Network Adapters with Promiscuous Mode" "powershell -Command \"Get-NetAdapter | Select-Object Name,InterfaceDescription,PromiscuousMode,Status | Format-Table -AutoSize\""
call :CollectData "%NETWORK_INFO%" "Network Connections" "netstat -ano"
call :CollectData "%NETWORK_INFO%" "Listening Ports" "netstat -ano | find \"LISTENING\""
call :CollectData "%NETWORK_INFO%" "DNS Cache" "ipconfig /displaydns | find \"Record Name\""
call :CollectData "%NETWORK_INFO%" "Routing Table" "netstat -r"
call :CollectData "%NETWORK_INFO%" "ARP Cache" "arp -a"

:: ============================================
:: 5. FILE SYSTEM INFORMATION (Single File)
:: ============================================
set FILESYSTEM_INFO=%EVIDENCE_DIR%\05_File_System_Information.txt

call :CollectData "%FILESYSTEM_INFO%" "System32 Directory Listing" "dir C:\WINDOWS\system32 /o:d"
call :CollectData "%FILESYSTEM_INFO%" "Recent Files in System32" "dir C:\WINDOWS\system32 /o:d | findstr /i \".exe$\|.dll$\|.sys$\" | head -20"
call :CollectData "%FILESYSTEM_INFO%" "Root Directory" "dir C:\ /a"
call :CollectData "%FILESYSTEM_INFO%" "Windows Directory" "dir C:\Windows /a"
call :CollectData "%FILESYSTEM_INFO%" "Program Files Directories" "dir \"C:\Program Files\" /a && echo. && dir \"C:\Program Files (x86)\" /a"

:: ============================================
:: 6. AUTOMATION AND SCHEDULING (Single File)
:: ============================================
set AUTOMATION_INFO=%EVIDENCE_DIR%\06_Automation_and_Scheduling.txt

call :CollectData "%AUTOMATION_INFO%" "Scheduled Tasks" "schtasks"
call :CollectData "%AUTOMATION_INFO%" "Detailed Scheduled Tasks" "schtasks /query /fo csv /v"
call :CollectData "%AUTOMATION_INFO%" "HKLM Autorun Entries" "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
call :CollectData "%AUTOMATION_INFO%" "HKCU Autorun Entries" "reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
call :CollectData "%AUTOMATION_INFO%" "Startup Folder Locations" "dir \"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\" /a && echo. && dir \"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\" /a"

:: ============================================
:: 7. SECURITY SETTINGS (Single File)
:: ============================================
set SECURITY_INFO=%EVIDENCE_DIR%\07_Security_Settings.txt

call :CollectData "%SECURITY_INFO%" "Firewall Current Profile" "netsh advfirewall show currentprofile"
call :CollectData "%SECURITY_INFO%" "Firewall All Profiles" "netsh advfirewall show allprofiles"
call :CollectData "%SECURITY_INFO%" "Firewall Rules Count" "netsh advfirewall firewall show rule name=all"
call :CollectData "%SECURITY_INFO%" "Windows Defender Status" "powershell -Command \"Get-MpComputerStatus | Select-Object *\" 2>nul || echo Windows Defender not available or not running"
call :CollectData "%SECURITY_INFO%" "Audit Policy" "auditpol /get /category:*"

:: ============================================
:: 8. NETWORK SHARES AND SESSIONS (Single File)
:: ============================================
set SHARES_INFO=%EVIDENCE_DIR%\08_Shares_and_Sessions.txt

call :CollectData "%SHARES_INFO%" "Local Shares" "net share"
call :CollectData "%SHARES_INFO%" "Network Shares View" "net view \\127.0.0.1"
call :CollectData "%SHARES_INFO%" "Open Sessions" "net sessions"
call :CollectData "%SHARES_INFO%" "Open Files" "net file"
call :CollectData "%SHARES_INFO%" "Network Connections (Detailed)" "net use"
call :CollectData "%SHARES_INFO%" "SMB Sessions" "powershell -Command \"Get-SmbSession\" 2>nul || echo SMB Session command not available"

:: ============================================
:: 9. ADDITIONAL FORENSIC ARTIFACTS (Single File)
:: ============================================
set FORENSIC_INFO=%EVIDENCE_DIR%\09_Additional_Forensic_Artifacts.txt

call :CollectData "%FORENSIC_INFO%" "Installed Software (HKLM)" "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
call :CollectData "%FORENSIC_INFO%" "Installed Software (WOW64)" "reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
call :CollectData "%FORENSIC_INFO%" "Recent Commands" "doskey /history"
call :CollectData "%FORENSIC_INFO%" "Environment Variables" "set"
call :CollectData "%FORENSIC_INFO%" "System Drivers" "driverquery"
call :CollectData "%FORENSIC_INFO%" "Patch Information" "wmic qfe get Caption,Description,HotFixID,InstalledOn"

:: ============================================
:: 10. QUICK SYSTEM STATE (Single File - Triage)
:: ============================================
set TRIAGE_INFO=%EVIDENCE_DIR%\10_Triage_Summary.txt

call :CollectData "%TRIAGE_INFO%" "CRITICAL: Suspicious Processes" "tasklist | findstr /i \"miner\|mimikatz\|cobalt\|empire\|meterpreter\|powersploit\" || echo No obvious suspicious process names found"
call :CollectData "%TRIAGE_INFO%" "CRITICAL: Unusual Listening Ports" "netstat -ano | findstr \":443\|:4444\|:8080\|:8443\""
call :CollectData "%TRIAGE_INFO%" "CRITICAL: Hidden Files in Root" "dir C:\ /a:h"
call :CollectData "%TRIAGE_INFO%" "CRITICAL: New Services" "wmic service where \"startmode='auto' and state='running'\" get name,pathname | findstr /v \"Microsoft\|Windows\""

:: ============================================
:: FINALIZATION
:: ============================================
set FINAL_LOG=%EVIDENCE_DIR%\00_COLLECTION_COMPLETE.txt

echo ============================================ > "%FINAL_LOG%"
echo INCIDENT RESPONSE COLLECTION COMPLETE >> "%FINAL_LOG%"
echo ============================================ >> "%FINAL_LOG%"
echo. >> "%FINAL_LOG%"
echo Collection Summary: >> "%FINAL_LOG%"
echo ------------------- >> "%FINAL_LOG%"
echo Start Time: %date% %time% >> "%FINAL_LOG%"
echo Computer: %COMPUTERNAME% >> "%FINAL_LOG%"
echo User: %USERNAME% >> "%FINAL_LOG%"
echo Evidence Directory: %EVIDENCE_DIR% >> "%FINAL_LOG%"
echo. >> "%FINAL_LOG%"

echo Files Collected: >> "%FINAL_LOG%"
dir "%EVIDENCE_DIR%\*.txt" /b >> "%FINAL_LOG%"
echo. >> "%FINAL_LOG%"

echo File Sizes: >> "%FINAL_LOG%"
for %%F in ("%EVIDENCE_DIR%\*.txt") do (
    for %%S in (%%~zF) do (
        echo %%~nxF - %%~S bytes >> "%FINAL_LOG%"
    )
)

echo. >> "%FINAL_LOG%"
echo Collection completed at: %time% on %date% >> "%FINAL_LOG%"
echo ============================================ >> "%FINAL_LOG%"

:: Create a quick hash of all collected files
echo Creating file hashes for integrity verification...
powershell -Command "Get-FileHash '%EVIDENCE_DIR%\*.txt' -Algorithm MD5 | Format-Table -AutoSize" > "%EVIDENCE_DIR%\file_hashes_md5.txt"

:: Final output
echo.
echo ============================================
echo COLLECTION COMPLETE
echo ============================================
echo.
echo Evidence stored in: %EVIDENCE_DIR%
echo.
echo Files Created:
echo --------------
dir "%EVIDENCE_DIR%\*.txt" /b
echo.
echo Total evidence files: 
dir "%EVIDENCE_DIR%\*.txt" | find /c "File(s)"
echo.
echo Review the triage summary: %EVIDENCE_DIR%\10_Triage_Summary.txt
echo.
echo Press any key to open the evidence directory...
pause >nul

explorer "%EVIDENCE_DIR%"
