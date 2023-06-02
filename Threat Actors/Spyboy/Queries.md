# Splunk
## TTP hunt
```
index=sysmon EventCode=11 "drivers" "system32"
| regex file_path="^\w+\:\\\Windows\\\System32\\\drivers\\\.*"
| regex file_name="^[a-zA-Z]{4,10}\.sys$"
| stats count(host) as writeCount by file_name, file_path
| where writeCount < 5
```

# MS Defender
## TTP hunt
```
DeviceFileEvents 
| where ActionType == 'FileCreated' 
| where FolderPath matches regex @"^\w+\:\\Windows\\System32\\drivers\\"
| where FileName matches regex @"^[a-zA-Z]{4,10}\.sys$"
| summarize writeCount = count() by FileName, FolderPath, SHA256
| where writeCount < 5
```

# CrowdStrike
## TTP hunt
```
event_platform=Win event_simpleName=PeFileWritten "drivers" "system32"
| regex FilePath="^\\\Device\\\HarddiskVolume\d+\\\Windows\\\System32\\\drivers\\\$"
| regex FileName="^[a-zA-Z]{4,10}\.sys$"
| stats count(aid) as writeCount by SHA256HashData, FileName, FilePath
| where writeCount < 5
