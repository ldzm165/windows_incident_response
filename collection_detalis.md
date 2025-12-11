### Requirements
- **Windows 7/8/10/11** or **Windows Server 2008 R2+**
- **Administrator privileges** (recommended for full collection)
- **PowerShell** (enabled and accessible)
- **Minimum disk space**: 50-100MB for evidence storage

## Evidence Collection Details

### What Gets Collected (10 Logical Categories)

#### 1. System Information (`01_System_Information.txt`)
- Collection timestamp and system time
- Operating system details and version
- System uptime and timezone
- Manufacturer and system name

#### 2. User and Group Information (`02_User_and_Group_Information.txt`)
- Current user context and privileges
- All user accounts on the system
- Local group memberships (including Administrators)
- Account lockout and password policies
- Currently logged on users

#### 3. Process and Service Information (`03_Process_and_Service_Information.txt`)
- Running processes with service mappings
- Process command lines and executable paths
- DLLs loaded by each process
- Running services and their configurations
- Service startup types and states

#### 4. Network Configuration (`04_Network_Configuration.txt`)
- IP configuration and network adapters
- Promiscuous mode detection
- Active network connections and listening ports
- DNS cache and routing tables
- ARP cache entries

#### 5. File System Information (`05_File_System_Information.txt`)
- System32 directory listing (ordered by date)
- Recent executables and DLLs in System32
- Root directory and Windows directory contents
- Program Files directories listing

#### 6. Automation and Scheduling (`06_Automation_and_Scheduling.txt`)
- Scheduled tasks (basic and detailed views)
- Registry autorun entries (HKLM and HKCU)
- Startup folder contents
- Task automation configurations

#### 7. Security Settings (`07_Security_Settings.txt`)
- Windows Firewall profiles and rules
- Windows Defender status (if available)
- Audit policies and security settings
- Advanced firewall configurations

#### 8. Shares and Sessions (`08_Shares_and_Sessions.txt`)
- Local file shares and permissions
- Network shares view
- Open sessions and active connections
- SMB session information
- Currently open files

#### 9. Additional Forensic Artifacts (`09_Additional_Forensic_Artifacts.txt`)
- Installed software (from registry)
- Command history (if available)
- Environment variables
- System drivers
- Installed patches and updates

#### 10. Triage Summary (`10_Triage_Summary.txt`)
- **CRITICAL FINDINGS**: Immediate indicators of compromise
- Suspicious process names (common malware/attack tools)
- Unusual listening ports (443, 4444, 8080, 8443)
- Hidden files in root directory
- Non-Microsoft auto-start services

### Supporting Files
- `00_COLLECTION_COMPLETE.txt` - Collection metadata and file inventory
- `collection_summary.txt` - Execution log with timestamps
- `file_hashes_md5.txt` - Integrity verification hashes

## Usage Instructions

### Standard Collection
```batch
# Simply execute the batch file
ir_windows.bat
