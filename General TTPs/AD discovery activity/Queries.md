# Splunk
## TTP hunt
```
| tstats `security_content_summariesonly` count dc(Processes.process_name) as procCount, earliest(_time) as firstTime latest(_time) as lastTime, values(Processes.process_name) as procRun, values(Processes.process) as cmdsRun
from datamodel=Endpoint.Processes
where Processes.process IN ("net*group*\"Domain*Computers\"*/domain*","net*group*/domain*\"Domain*Computers\"*","net*group*\"Domain*Admins\"*/domain*","net*group*/domain*\"Domain*Admins\"*","net*group*\"Domain*Admins\"*/domain*","net*group*/domain*\"Enterprise*Admins\"*","net*group*\"Enterprise*Admins\"*/domain*","systeminfo*","net*users*","net*share*","net*view*","nltest*/DOMAIN_TRUSTS*","ipconfig*/all*","find.exe*-f*\"(objectcategory=person)\"*","find.exe*-f*\"objectcategory=computer\"*","find.exe*-f*\"(objectcategory=organizationalUnit)\"*","find.exe*-sc*trustdmp*","find.exe*-subnets*-f*(objectCategory=subnet)*","find.exe*-f*\"(objectcategory=group)\"*","find.exe*-gcb*-sc*trustdmp*") by Processes.user, Processes.dest, Processes.parent_process_name, Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime), ctime(lastTime)
| table dest, user, parent_process_name, procRun, cmdsRun, firstTime, lastTime
```

# MS Defender
## TTP hunt
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where FileName in~ ("net.exe", "net1.exe", "find.exe", "cmd.exe", "systeminfo.exe", "ipconfig.exe", "nltest.exe")
| where ProcessCommandLine has_any ("Domain Computers", "Domain Admins", "Enterprise Admins", "systeminfo", "net  users", "net  share", "net  view", "nltest", "ipconfig /all", "objectcategory=person", "objectcategory=computer", "objectcategory=organizationalUnit", "trustdmp", "objectCategory=subnet", "objectcategory=group")
| summarize Min = min(Timestamp), Max = max(Timestamp), procRun = make_set(FileName), cmdsRun = make_list(ProcessCommandLine) by DeviceName, AccountDomain, AccountName, InitiatingProcessFileName, InitiatingProcessId
| project DeviceName, AccountDomain, AccountName, InitiatingProcessFileName, procRun, cmdsRun, Min, Max
```

# CrowdStrike
## TTP hunt
```
event_platform=win event_simpleName=ProcessRollup2 CommandLine IN ("net*group*\"Domain*Computers\"*/domain*","net*group*/domain*\"Domain*Computers\"*","net*group*\"Domain*Admins\"*/domain*","net*group*/domain*\"Domain*Admins\"*","net*group*\"Domain*Admins\"*/domain*","net*group*/domain*\"Enterprise*Admins\"*","net*group*\"Enterprise*Admins\"*/domain*","systeminfo*","net*users*","net*share*","net*view*","nltest*/DOMAIN_TRUSTS*","ipconfig*/all*","find.exe*-f*\"(objectcategory=person)\"*","find.exe*-f*\"objectcategory=computer\"*","find.exe*-f*\"(objectcategory=organizationalUnit)\"*","find.exe*-sc*trustdmp*","find.exe*-subnets*-f*(objectCategory=subnet)*","find.exe*-f*\"(objectcategory=group)\"*","find.exe*-gcb*-sc*trustdmp*")
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| eval graphExplorer=case(ParentProcessId_decimal!="","https://falcon.eu-1.crowdstrike.com/graphs/process-explorer/tree?id=pid:".aid.":".ParentProcessId_decimal)
| convert ctime(firstRun), ctime(lastRun)
| table cid, aid, ComputerName, ParentBaseFileName, filesRun, cmdsRun, firstRun, lastRun, graphExplorer
```