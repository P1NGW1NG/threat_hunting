# Splunk
## TTP hunt
```
| tstats summariesonly=false allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=bitsadmin.exe OR Processes.original_file_name=bitsadmin.exe) Processes.process IN ("*transfer*", "*addfile*") by Processes.dest Processes.user Processes.parent_process Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| rename "Processes.*" as * 
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) 
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
```

# MS Defender
## TTP hunt
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where ProcessCommandLine has_any ("transfer", "addfile")
and FileName in~ ("bitsadmin.exe")
| summarize Min = min(Timestamp), Max = max(Timestamp) by DeviceName, AccountDomain, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, FileName, ProcessCommandLine
| project DeviceName, AccountDomain, AccountName, Min, Max, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

# CrowdStrike
## TTP hunt
```
event_platform=win event_simpleName=ProcessRollup2 FileName IN ("bitsadmin.exe") CommandLine IN ("*transfer*", "*addfile*") | stats earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(CommandLine) as cmdsRun by cid, aid, company, ComputerName, ParentBaseFileName, ParentProcessId_decimal, FileName
| convert ctime(firstRun), ctime(lastRun)
| table cid, aid, company, ComputerName, firstRun, lastRun, ParentBaseFileName, FileName, cmdsRun
```