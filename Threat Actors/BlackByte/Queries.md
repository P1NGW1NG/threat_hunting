# Splunk
## IOC hunt
```
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("*545eee18d387e70c68afc9701432766b0376dc9bc1eace031f5df69ec72f0cd8*", "*884e96a75dc568075e845ccac2d4b4ccec68017e6ef258c7c03da8c88a597534*", "*545eee18d387e70c68afc9701432766b0376dc9bc1eace031f5df69ec72f0cd8*") by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## TTP hunt
```
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN
("*vssadmin* Resize ShadowStorage /For=C: /On=C: /MaxSize=*",
"*netsh* advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes*",
"*netsh* advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes*",
"*netsh* advfirewall set allprofiles state off",
"*reg* add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f",
"*cmd* /c del C:\\Windows\\System32\\Taskmgr.exe /f /q & del C:\\Windows\\System32\\resmon.exe /f /q & powershell -command \"$x = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(\'Vw\'+\'BpAG4A\'+\'RAB\'+\'lA\'+\'GYAZQ\'+\'Bu\'+\'A\'+\'GQA\'));Stop-Service -Name $x;Set-Service -StartupType Disabled $x",
"*powershell* Get-CimInstance Win32_ShadowCopy | Remove-CimInstance",
"*powershell* Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
Processes.parent_process_name IN ("*") by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```


# MS Defender
## IOC hunt
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where SHA256 in ("545eee18d387e70c68afc9701432766b0376dc9bc1eace031f5df69ec72f0cd8", "884e96a75dc568075e845ccac2d4b4ccec68017e6ef258c7c03da8c88a597534", "545eee18d387e70c68afc9701432766b0376dc9bc1eace031f5df69ec72f0cd8")
| project Timestamp, DeviceName, AccountDomain, AccountName, ProcessId, ProcessCommandLine, FileName, FolderPath, SHA256, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256 
```

## TTP hunt
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where FileName in~ ("net.exe") 
| where ProcessCommandLine has "Resize ShadowStorage /For=C: /On=C: /MaxSize=" 
   or ProcessCommandLine has "advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes" 
   or ProcessCommandLine has "advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes"
   or ProcessCommandLine has "advfirewall set allprofiles state off"
   or ProcessCommandLine has "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
   or ProcessCommandLine has "/c del C:\\Windows\\System32\\Taskmgr.exe /f /q & del C:\\Windows\\System32\\resmon.exe /f /q & powershell -command \"$x = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(\'Vw\'+\'BpAG4A\'+\'RAB\'+\'lA\'+\'GYAZQ\'+\'Bu\'+\'A\'+\'GQA\'));Stop-Service -Name $x;Set-Service -StartupType Disabled $x"
   or ProcessCommandLine has "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance"
   or ProcessCommandLine has "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
| project Timestamp, DeviceName, AccountDomain, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

# CrowdStrike
## IOC hunt
```
index=main event_simpleName=ProcessRollup2 SHA256HashData IN ('545eee18d387e70c68afc9701432766b0376dc9bc1eace031f5df69ec72f0cd8', '884e96a75dc568075e845ccac2d4b4ccec68017e6ef258c7c03da8c88a597534', '545eee18d387e70c68afc9701432766b0376dc9bc1eace031f5df69ec72f0cd8')
|  stats count, earliest(_time) as first_triggered, latest(_time) as latest_triggered by company, ComputerName, CommandLine, FileName, FilePath, SHA256HashData 
|  convert ctime(first_triggered), ctime(latest_triggered)
```

## TTP hunt
```
index=main event_simpleName=ProcessRollup2 CommandLine IN 
("*vssadmin* Resize ShadowStorage /For=C: /On=C: /MaxSize=*",
"*netsh* advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes*",
"*netsh* advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes*",
"*netsh* advfirewall set allprofiles state off",
"*reg* add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f",
"*cmd* /c del C:\\Windows\\System32\\Taskmgr.exe /f /q & del C:\\Windows\\System32\\resmon.exe /f /q & powershell -command \"$x = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(\'Vw\'+\'BpAG4A\'+\'RAB\'+\'lA\'+\'GYAZQ\'+\'Bu\'+\'A\'+\'GQA\'));Stop-Service -Name $x;Set-Service -StartupType Disabled $x",
"*powershell* Get-CimInstance Win32_ShadowCopy | Remove-CimInstance",
"*powershell* Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
|  stats count, earliest(_time) as first_triggered, latest(_time) as latest_triggered by company, ComputerName, CommandLine, FileName, FilePath, SHA256HashData 
|  convert ctime(first_triggered), ctime(latest_triggered)
