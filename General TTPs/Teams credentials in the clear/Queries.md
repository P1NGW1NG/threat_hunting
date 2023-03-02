# Splunk
## TTP hunt
```
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where 
NOT Processes.process_name IN ("Teams.exe") by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process_hash
| regex process="(?i).*(\\|\/)microsoft(\\|\/)(microsoft\s)?teams(\\|\/)(cookies|local\s+storage(\\|\/)leveldb).*"
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

# MS Defender
## TTP hunt on file events
```
DeviceFileEvents
| where Timestamp > ago(30d) 
| where FolderPath matches regex @"(?i).*(\\|\/)microsoft(\\|\/)(microsoft\s)?teams(\\|\/)(cookies|local\s+storage(\\|\/)leveldb).*"
| where InitiatingProcessFileName != "Teams.exe"
| project Timestamp, FileName, FolderPath, FileSize, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath 
```

## TTP hunt on process events
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where ProcessCommandLine matches regex @"(?i).*(\\|\/)microsoft(\\|\/)(microsoft\s)?teams(\\|\/)(cookies|local\s+storage(\\|\/)leveldb).*"
| project Timestamp, DeviceName, AccountDomain, AccountName, ProcessId, ProcessCommandLine, FileName, FolderPath, SHA256, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
```

# CrowdStrike
## TTP hunt
```
event_platform IN (win, mac, lin) event_simpleName=ProcessRollup2
| regex CommandLine="(?i).*(\\\\|\/)microsoft(\\\\|\/)(microsoft\s)?teams(\\\\|\/)(cookies|local\s+storage(\\\\|\/)leveldb).*"
| stats dc(aid) as uniqueEndpoints, count(aid) as invocationCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(CommandLine) as cmdLines by ParentBaseFileName, FileName
| convert ctime(firstRun), ctime(lastRun)
```