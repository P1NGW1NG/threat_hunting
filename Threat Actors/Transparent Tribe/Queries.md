# Splunk
## IOC hunt
```
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("*bdeb9d019a02eb49c21f7c04169406ac586d630032a059f63c497951303b8d00*", "*388f212dfca2bfb5db0a8b9958a43da6860298cdd4fcd53ed2c75e3b059ee622*", "*0d61d5fe8dbf69c6e61771451212fc8e587d93246bd866adf1031147d6d4f8c2*", "*14ee2e3a9263bab359bc19050567d0dbd6371c8c0a7c6aeba71adbf5df2fc35b*", "*8c1a5052bf3c1b33aff9e249ae860ea1435ce716d5b5be2ec3407520507c6d37*", "*79aee357ea68d8f66b929ba2e57465eaee4d965b0da5001fe589afe1588874e3*", "*8b786784c172c6f8b241b1286a2054294e8dc2c167d9b4daae0e310a1d923ba0*", "*b4819738a277090405f0b5bbcb31d5dd3115f7026401e5231df727da0443332a*", "*e2cf71c78d198fdc0017b7bfd6ce8115301174302b3eaaf50cfc384db96bc573*", "*8c9b0fd259e7f016f53be8edc53fe5f908b48ae691e21f0f820da11429e595d8*", "*f3a1ac021941b481ac7e2335b74ebf1e44728e8917381728f1f5b390c6f34706*", "*fc34f9087ab199d0bac22aa97de48e5592dbf0784342b9ecd01b4a429272ab5b*", "*b3f8e026f39056ec5e66700e03eeaf57454ee9c0bc1c719d74e10f5702957305*", "*9159d4e354218870461c96bedcc7b5b026f872d30235bb4536cc4a5ce4154725*", "*b614436bf9461b80384bae937d699f8c3886bcc65b907e0c8126b4df59ea8cdb*", "*28390e3ea8a547f05ca08551f484292d46398a2b38fd4aae001ac7d056c5abc0*") by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## IOC hunt
```
(`cim_Network_Resolution_indexes`) tag=network tag=resolution tag=dns
| search QueryName IN ("*studentsportal.live*", "*geo-news.tv*", "*cloud-drive.store*", "*user-onedrive.live*", "*drive-phone.online*", "*studentsportal.co*", "*studentsportal.website*", "*nsdrive-phone.online*", "*statefinancebank.com*", "*in.statefinancebank.com*", "*centralink.online*", "*cloud-drive.geo-news.tv*", "*drive-phone.geo-news.tv*", "*studentsportal.geo-news.tv*", "*user-onedrive.geo-news.tv*", "*studentsportal.live.geo-news.tv*", "*phone-drive.online.geo-news.tv*", "*sunnyleone.hopto.org*", "*swissaccount.ddns.net*")
| stats count by host, QueryName, QueryResults, QueryStatus
```

# MS Defender
## IOC hunt
```
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where SHA256 in ("bdeb9d019a02eb49c21f7c04169406ac586d630032a059f63c497951303b8d00", "388f212dfca2bfb5db0a8b9958a43da6860298cdd4fcd53ed2c75e3b059ee622", "0d61d5fe8dbf69c6e61771451212fc8e587d93246bd866adf1031147d6d4f8c2", "14ee2e3a9263bab359bc19050567d0dbd6371c8c0a7c6aeba71adbf5df2fc35b", "8c1a5052bf3c1b33aff9e249ae860ea1435ce716d5b5be2ec3407520507c6d37", "79aee357ea68d8f66b929ba2e57465eaee4d965b0da5001fe589afe1588874e3", "8b786784c172c6f8b241b1286a2054294e8dc2c167d9b4daae0e310a1d923ba0", "b4819738a277090405f0b5bbcb31d5dd3115f7026401e5231df727da0443332a", "e2cf71c78d198fdc0017b7bfd6ce8115301174302b3eaaf50cfc384db96bc573", "8c9b0fd259e7f016f53be8edc53fe5f908b48ae691e21f0f820da11429e595d8", "f3a1ac021941b481ac7e2335b74ebf1e44728e8917381728f1f5b390c6f34706", "fc34f9087ab199d0bac22aa97de48e5592dbf0784342b9ecd01b4a429272ab5b", "b3f8e026f39056ec5e66700e03eeaf57454ee9c0bc1c719d74e10f5702957305", "9159d4e354218870461c96bedcc7b5b026f872d30235bb4536cc4a5ce4154725", "b614436bf9461b80384bae937d699f8c3886bcc65b907e0c8126b4df59ea8cdb", "28390e3ea8a547f05ca08551f484292d46398a2b38fd4aae001ac7d056c5abc0")
| project Timestamp, DeviceName, AccountDomain, AccountName, ProcessId, ProcessCommandLine, FileName, FolderPath, SHA256, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256 
```

## IOC hunt
```
search in (DeviceNetworkEvents, DeviceFileEvents, DeviceEvents)
Timestamp > ago(30d)
| where RemoteUrl contains "studentsportal.live"
or RemoteUrl contains "geo-news.tv"
or RemoteUrl contains "cloud-drive.store"
or RemoteUrl contains "user-onedrive.live"
or RemoteUrl contains "drive-phone.online"
or RemoteUrl contains "studentsportal.co"
or RemoteUrl contains "studentsportal.website"
or RemoteUrl contains "nsdrive-phone.online"
or RemoteUrl contains "statefinancebank.com"
or RemoteUrl contains "in.statefinancebank.com"
or RemoteUrl contains "centralink.online"
or RemoteUrl contains "cloud-drive.geo-news.tv"
or RemoteUrl contains "drive-phone.geo-news.tv"
or RemoteUrl contains "studentsportal.geo-news.tv"
or RemoteUrl contains "user-onedrive.geo-news.tv"
or RemoteUrl contains "studentsportal.live.geo-news.tv"
or RemoteUrl contains "phone-drive.online.geo-news.tv"
or RemoteUrl contains "sunnyleone.hopto.org"
or RemoteUrl contains "swissaccount.ddns.net" 
or FileOriginUrl contains "studentsportal.live"
or FileOriginUrl contains "geo-news.tv"
or FileOriginUrl contains "cloud-drive.store"
or FileOriginUrl contains "user-onedrive.live"
or FileOriginUrl contains "drive-phone.online"
or FileOriginUrl contains "studentsportal.co"
or FileOriginUrl contains "studentsportal.website"
or FileOriginUrl contains "nsdrive-phone.online"
or FileOriginUrl contains "statefinancebank.com"
or FileOriginUrl contains "in.statefinancebank.com"
or FileOriginUrl contains "centralink.online"
or FileOriginUrl contains "cloud-drive.geo-news.tv"
or FileOriginUrl contains "drive-phone.geo-news.tv"
or FileOriginUrl contains "studentsportal.geo-news.tv"
or FileOriginUrl contains "user-onedrive.geo-news.tv"
or FileOriginUrl contains "studentsportal.live.geo-news.tv"
or FileOriginUrl contains "phone-drive.online.geo-news.tv"
or FileOriginUrl contains "sunnyleone.hopto.org"
or FileOriginUrl contains "swissaccount.ddns.net"
or RemoteIP in("192.3.99.68", "198.37.123.126")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, FileOriginUrl, ActionType
```

# CrowdStrike
## IOC hunt
```
index=main event_simpleName=ProcessRollup2 SHA256HashData IN ("bdeb9d019a02eb49c21f7c04169406ac586d630032a059f63c497951303b8d00", "388f212dfca2bfb5db0a8b9958a43da6860298cdd4fcd53ed2c75e3b059ee622", "0d61d5fe8dbf69c6e61771451212fc8e587d93246bd866adf1031147d6d4f8c2", "14ee2e3a9263bab359bc19050567d0dbd6371c8c0a7c6aeba71adbf5df2fc35b", "8c1a5052bf3c1b33aff9e249ae860ea1435ce716d5b5be2ec3407520507c6d37", "79aee357ea68d8f66b929ba2e57465eaee4d965b0da5001fe589afe1588874e3", "8b786784c172c6f8b241b1286a2054294e8dc2c167d9b4daae0e310a1d923ba0", "b4819738a277090405f0b5bbcb31d5dd3115f7026401e5231df727da0443332a", "e2cf71c78d198fdc0017b7bfd6ce8115301174302b3eaaf50cfc384db96bc573", "8c9b0fd259e7f016f53be8edc53fe5f908b48ae691e21f0f820da11429e595d8", "f3a1ac021941b481ac7e2335b74ebf1e44728e8917381728f1f5b390c6f34706", "fc34f9087ab199d0bac22aa97de48e5592dbf0784342b9ecd01b4a429272ab5b", "b3f8e026f39056ec5e66700e03eeaf57454ee9c0bc1c719d74e10f5702957305", "9159d4e354218870461c96bedcc7b5b026f872d30235bb4536cc4a5ce4154725", "b614436bf9461b80384bae937d699f8c3886bcc65b907e0c8126b4df59ea8cdb", "28390e3ea8a547f05ca08551f484292d46398a2b38fd4aae001ac7d056c5abc0")
|  stats count, earliest(_time) as first_triggered, latest(_time) as latest_triggered by company, ComputerName, CommandLine, FileName, FilePath, SHA256HashData 
|  convert ctime(first_triggered), ctime(latest_triggered)
```

## IOC hunt
TIP: You can use the dedicated hunt dashboards for these IOC hunts:
* [Domain Bulk Search](https://falcon.eu-1.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__domain_bulk)
```
search (DnsRequest OR SuspiciousDnsRequest) cid=*
[| stats count
	| eval DomainName="studentsportal.live geo-news.tv cloud-drive.store user-onedrive.live drive-phone.online studentsportal.co studentsportal.website nsdrive-phone.online statefinancebank.com in.statefinancebank.com centralink.online cloud-drive.geo-news.tv drive-phone.geo-news.tv studentsportal.geo-news.tv user-onedrive.geo-news.tv studentsportal.live.geo-news.tv phone-drive.online.geo-news.tv sunnyleone.hopto.org swissaccount.ddns.net"
	| makemv DomainName delim=" "
	| fields DomainName ]
| eval DomainName=lower(DomainName)
| stats values(ComputerName) AS "Host Name", count AS Count, dc(ComputerName) AS "# of Hosts", last(ComputerName) AS "First Lookup By", min(_time) AS FirstLookupDate, latest(ComputerName) AS "Last Lookup By", max(_time) AS LastLookupDate by DomainName
| eval WHOIS="Check Now"
| eval "First Lookup Date"=FirstLookupDate
| eval "Last Lookup Date"=LastLookupDate
| convert ctime("First Lookup Date")
| convert ctime("Last Lookup Date")
| table DomainName, "Host Name", "# of Hosts", "First Lookup By", "First Lookup Date", "Last Lookup By", "Last Lookup Date", WHOIS, FirstLookupDate, LastLookupDate
| rename DomainName AS "Domain Name"
```