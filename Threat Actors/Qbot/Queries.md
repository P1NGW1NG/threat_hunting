# Splunk
## TTP hunt
```
| tstats `security_content_summariesonly` count dc(Processes.process_name) as procCount, earliest(_time) as firstTime latest(_time) as lastTime, values(Processes.process_name) as procRun, values(Processes.process) as cmdsRun
from datamodel=Endpoint.Processes
where Processes.process_name IN (whoami.exe, arp.exe, cmd.exe, net.exe, net1.exe, ipconfig.exe, route.exe, netstat.exe, nslookup.exe, nltest.exe)
by Processes.user, Processes.dest, Processes.parent_process_name, Processes.parent_process_id
| where procCount > 3
| `drop_dm_object_name(Processes)`
| eval timeDelta=lastTime-firstTime
| where timeDelta < 600
| convert ctime(firstTime), ctime(lastTime)
| table dest, user, parent_process_name, procRun, cmdsRun, firstTime, lastTime, timeDelta
```

# MS Defender
## TTP hunt
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where FileName in~ ("whoami.exe", "arp.exe", "cmd.exe", "net.exe", "net1.exe", "ipconfig.exe", "route.exe", "netstat.exe", "nslookup.exe", "nltest.exe")
| summarize procCount = dcount(FileName), Min = min(Timestamp), Max = max(Timestamp), timeDelta = max(Timestamp)-min(Timestamp), procRun = make_set(FileName), cmdsRun = make_list(ProcessCommandLine) by DeviceName, AccountDomain, AccountName, InitiatingProcessFileName, InitiatingProcessId
| where procCount > 3
| where timeDelta < 10m
| project DeviceName, AccountDomain, AccountName, InitiatingProcessFileName, procRun, cmdsRun, Min, Max, timeDelta
```

# CrowdStrike
## TTP hunt
```
event_platform=win event_simpleName=ProcessRollup2 FileName IN (whoami.exe, arp.exe, cmd.exe, net.exe, net1.exe, ipconfig.exe, route.exe, netstat.exe, nslookup.exe, nltest.exe)
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by cid, aid, company, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| where fnameCount > 3
| eval timeDelta=lastRun-firstRun
| where timeDelta < 600
| eval graphExplorer=case(ParentProcessId_decimal!="","https://falcon.eu-1.crowdstrike.com/graphs/process-explorer/tree?id=pid:".aid.":".ParentProcessId_decimal)
| convert ctime(firstRun), ctime(lastRun)
| table cid, aid, company, ComputerName, ParentBaseFileName, filesRun, cmdsRun, firstRun, lastRun, timeDelta, graphExplorer
```