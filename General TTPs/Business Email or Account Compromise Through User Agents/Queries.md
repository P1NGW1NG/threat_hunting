# MS Defender
## TTP hunt
```
AADSignInEventsBeta 
| where Timestamp > ago(30d)
| where UserAgent contains "azsdk-python"
| where ErrorCode == 0
| project Timestamp, AccountDisplayName, AccountUpn, IPAddress, Country, ErrorCode, UserAgent, Application, ConditionalAccessPolicies, ConditionalAccessStatus
```

# MS Defender
## TTP hunt - Follow-up outlying result of a single account to check blast radius in case of successful log-ons
```
AADSignInEventsBeta 
| where Timestamp > ago(30d)
| where AccountDisplayName == "CHANGEME" and IPAddress == "CHANGEME"
| where ErrorCode == 0
| project Timestamp, AccountDisplayName, AccountUpn, IPAddress, Country, ErrorCode, UserAgent, Application, ConditionalAccessPolicies, ConditionalAccessStatus
```

# MS Sentinel
## TTP hunt
```
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "CHANGEME" and IPAddress == "CHANGEME"
| where Status.errorCode == 0
| project TimeGenerated, Status.errorCode, Status.failureReason, OperationName, ResultDescription, UserPrincipalName, IPAddress, Location, UserAgent, AppDisplayName
```

# MS Sentinel
## TTP hunt - Follow-up outlying result of a single account to check blast radius in case of successful log-ons
```
event_platform=win event_simpleName=ProcessRollup2 FileName="curl.exe" AND CommandLine IN ("*-O *","*--output*") AND CommandLine IN ("*appdata*","*programdata*","*public*", "*tmp*", "*temp*", "*PerfLogs*")
| stats earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(CommandLine) as cmdsRun by cid, aid, company, ComputerName, ParentBaseFileName, ParentProcessId_decimal, FileName
| convert ctime(firstRun), ctime(lastRun)
| table cid, aid, company, ComputerName, firstRun, lastRun, ParentBaseFileName, FileName, cmdsRun
```