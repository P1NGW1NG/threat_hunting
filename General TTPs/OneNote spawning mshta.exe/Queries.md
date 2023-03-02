# Splunk
## TTP hunt
```
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("mshta.exe") Processes.parent_process_name IN ("ONENOTE.EXE","ONENOTEM.EXE") by Processes.user Processes.process_name Processes.parent_process_name Processes.dest
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table dest, user, firstTime, lastTime, parent_process_name, parent_process, process_name, process
```

# MS Defender
## TTP hunt
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where InitiatingProcessFileName in~ ("onenote.exe", "onenotem.exe")
and FileName in~ 'mshta.exe'
| summarize Min = min(Timestamp), Max = max(Timestamp) by DeviceName, AccountDomain, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, FileName, ProcessCommandLine
| project DeviceName, AccountDomain, AccountName, Min, Max, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

# CrowdStrike
## TTP hunt
```
event_platform=win event_simpleName=ProcessRollup2 FileName IN ("mshta.exe") ParentBaseFileName IN ("ONENOTE.EXE","ONENOTEM.EXE")
| stats earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(CommandLine) as cmdsRun by cid, aid, company, ComputerName, ParentBaseFileName, ParentProcessId_decimal, FileName
| convert ctime(firstRun), ctime(lastRun)
| table cid, aid, company, ComputerName, firstRun, lastRun, ParentBaseFileName, FileName, cmdsRun
```