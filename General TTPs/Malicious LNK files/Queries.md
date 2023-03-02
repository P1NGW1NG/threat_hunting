# Splunk
## TTP hunt
```
index=sysmon TargetFilename IN ("*Microsoft\\Windows\\Recent*", "*AppData\\Local\\Temp*")
AND TargetFilename IN ("*.zip*.lnk", "*.rar*.lnk", "*.7z*.lnk", "*.iso*.lnk", "*.img*.lnk", "*.vhd*.lnk", "*vhdx*.lnk")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, TargetFilename
| convert ctime(firstTime), ctime(lastTime)
```

# MS Defender
## TTP hunt Archive LNK file launched
```
DeviceFileEvents 
| where FolderPath has "Appdata\\Local\\Temp"
| where FolderPath has_any (".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx")
| where FileName endswith ".lnk";
```

## TTP hunt LNK launched from external drive (ISO)
```
DeviceEvents 
| where ActionType == 'BrowserLaunchedToOpenUrl' 
| where RemoteUrl endswith ".lnk"
| where RemoteUrl !startswith "C:"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl
| parse RemoteUrl with Drive '\\' *
| extend Drive = tostring(Drive)
| where isnotempty(Drive)
```

# CrowdStrike
## TTP hunt
```
index=main event_simpleName=ProcessRollup2 LinkName IN ("D*.lnk", "E*.lnk", "F*.lnk", "G*.lnk", "H*.lnk", "I*.lnk", "J*.lnk", "K*.lnk", "L*.lnk", "M*.lnk", "N*.lnk", "O*.lnk", "P*.lnk", "Q*.lnk", "R*.lnk", "S*.lnk", "T*.lnk", "U*.lnk", "V*.lnk", "W*.lnk", "X*.lnk", "Y*.lnk", "Z*.lnk", "*.zip*.lnk", "*.rar*.lnk", "*.7z*.lnk", "*.iso*.lnk", "*.img*.lnk", "*.vhd*.lnk", "*vhdx*.lnk")
| stats count min(_time) as firstTime, max(_time) as lastTime by company, "Agent IP", ComputerName, LinkName, ImageFileName, CommandLine, ParentBaseFileName
| convert ctime(firstTime), ctime(lasTime)
```