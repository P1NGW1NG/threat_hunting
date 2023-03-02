# Splunk
## TTP hunt through reg.exe
```
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  Processes.process_name IN ("reg.exe") by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process_hash
| regex process="(?i).*(hklm\\\software\\\microsoft\\\windows\sdefender\\\exclusion\\\paths).*"
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## TTP hunt through PowerShell
```
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  Processes.process_name IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe") AND Processes.process IN ("*Add-MpPreference*", "*Set-MpPreference*") AND Processes.process IN ("*-Exclusion*") by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

# MS Defender
## TTP hunt through reg.exe
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where FileName =~ "reg.exe"
| where ProcessCommandLine matches regex @"(?i).*(hklm\\software\\microsoft\\windows\sdefender\\(exclusion|exclusions)\\paths).*"
| project Timestamp, FileName, ProcessCommandLine, FolderPath, FileSize, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath 
```

## TTP hunt through PowerShell
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where FileName in~  ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference")
| where ProcessCommandLine has "-Exclusion"
| project Timestamp, FileName, ProcessCommandLine, FolderPath, FileSize, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```

# CrowdStrike
## TTP hunt through reg.exe
```
event_platform IN (win) event_simpleName=ProcessRollup2
| regex CommandLine="(?i).*(hklm\\\software\\\microsoft\\\windows\sdefender\\\(exclusion|exclusions)\\\paths).*"
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by company, cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| eval graphExplorer=case(ParentProcessId_decimal!="","https://falcon.eu-1.crowdstrike.com/graphs/process-explorer/tree?id=pid:".aid.":".ParentProcessId_decimal)
| convert ctime(firstRun), ctime(lastRun)
| table company, cid, aid, ComputerName, ParentBaseFileName, filesRun, cmdsRun, firstRun, lastRun, graphExplorer
```

## TTP hunt through PowerShell
```
event_platform IN (win) event_simpleName=ProcessRollup2
AND FileName IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
AND CommandLine IN ("*Add-MpPreference*", "*Set-MpPreference*")
AND CommandLine IN ("*-Exclusion*")
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by company, cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| eval graphExplorer=case(ParentProcessId_decimal!="","https://falcon.eu-1.crowdstrike.com/graphs/process-explorer/tree?id=pid:".aid.":".ParentProcessId_decimal)
| convert ctime(firstRun), ctime(lastRun)
| table company, cid, aid, ComputerName, ParentBaseFileName, filesRun, cmdsRun, firstRun, lastRun, graphExplorer
```