# Splunk
## TTP hunt
```
index=sysmon EventID=8 SourceImage IN ("*powershell.exe", "*pwsh.exe", "*powershell_ise.exe") TargetImage="*rundll32.exe"
| stats earliest(_time) as firstSeen, latest(_time) as lastSeen, by host, SourceProcessId, SourceImage, TargetProcessId, TargetImage
```

# MS Defender
## TTP hunt
```
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType =~ "CreateRemoteThreadApiCall"
and ProcessId != InitiatingProcessId
and FileName =~ 'rundll32.exe'
and InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe") 
| project Timestamp, DeviceName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, ProcessCommandLine
```

# CrowdStrike
## TTP hunt
```
index=main event_platform=win event_simpleName IN (InjectedThread, ProcessRollup2) ParentBaseFileName IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe"), FileName="rundll32.exe"
| eval injectionTarget=if(match(event_simpleName,"InjectedThread"),TargetProcessId_decimal,null())
| eval processTarget=if(match(event_simpleName,"ProcessRollup2"),TargetProcessId_decimal,null())
| eval falconPID=coalesce(injectionTarget, processTarget) 
| stats dc(event_simpleName) as eventCount, values(ContextProcessId_decimal) as pidFileInjectedInto, values(ParentBaseFileName) as parentOfInjectingFile, values(FileName) as injectingFile, values(CommandLine) as injectingCommandLine by aid, ComputerName, falconPID
| where eventCount > 1
| eval ProcExplorer=case(pidFileInjectedInto!="","https://falcon.crowdstrike.com/investigate/process-explorer/" .aid. "/" . pidFileInjectedInto) 
```