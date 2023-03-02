Note, this search is very wobbly. Results may not be too accurate.
# Splunk
## TTP hunt
```
| tstats `security_content_summariesonly` count values(Filesystem.file_name) as file_name, values(Filesystem.file_hash) as file_hash, values(Filesystem.file_path) as file_path, values(Filesystem.vendor_product) as vendor_product, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*.iso", "*.iso.lnk", "*.img", "*.img.lnk", ) by Filesystem.action, Filesystem.dest, Filesystem.user
| convert ctime(firstTime), ctime(lastTime)
```

# MS Defender
## TTP hunt
```
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName endswith ".iso" or FileName endswith ".iso.lnk" or FileName endswith ".img" or FileName endswith ".img.lnk") and FolderPath contains "Windows\\Recent"
| project Timestamp, FileName, FolderPath, FileSize, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath 
```

# CrowdStrike
## TTP hunt (version 6.40+)
```
event_platform=win event_simpleName IN (FsVolumeMounted, RemovableMediaVolumeMounted, SnapshotVolumeMounted) VirtualDriveFileType_decimal=1 
| rex field=VirtualDriveFileName ".*\\\(?<isoName>.*\.(img|iso))"
| table ContextTimeStamp_decimal, aid, ComputerName, VolumeDriveLetter, VolumeName, isoName, VirtualDriveFileName
| rename ContextTimeStamp_decimal as endpointSystemClock, aid as agentID, ComputerName as computerName, VolumeDriveLetter as driveLetter, VolumeName as volumeName, VirtualDriveFileName as fullPath
| convert ctime(endpointSystemClock)
```

## TTP hunt (version 6.40-)
```
event_platform=win AND (event_simpleName IN ("GenericFileWritten", "NewExecutableWritten", "GzipFileWritten", "ZipFileWritten", "PeFileWritten")) AND (".iso" OR ".img")
|  stats earliest(_time) as firstSeen, latest(_time) as lastSeen by company, ComputerName, FileName, FilePath, TargetFileName
```