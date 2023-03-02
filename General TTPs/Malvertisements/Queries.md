# Splunk
## IOC hunt
```
(index=checkpoint OR index=fortinet)
| rename tls_server_host_name as hostname
| search dest IN ("5.149.248.2", "5.149.254.27", "5.149.248.15", "5.149.254.84", "5.149.254.68", "79.141.160.2")
OR hostname IN ("*ads-check.com*", "*down.software*", "*qtorrent.software*", "*winrar.software*", "*awesome-miner.software*", "*ccleaner.software*", "*mail-client.software*", "*top-wallet.software*", "*pdf-tools.software*", "*lightshot.software*", "*rufus-download.software*", "*downloaders.software*", "*any-desk.software*", "*down1.software*", "*download1.software*", "*vlc-media.software*", "*tor-browser.software*", "*rar-lab.software*", "*filezilla.space*", "*torrent-tools.software*", "*aimp.software*", "*archiver-7zip.software*", "*kmplayer.software*", "*notepad-editor.software*", "*amd-server2.life*", "*and-soft.online-application-form.com*", "*teamviewwer.tech*", "*nottepaddpluss.com*", "*geforse-drlvers.site*", "*download.winterlabs.click*", "*app1password.com*", "*app1password.com*", "*the1password.com*", "*docckeer.space*", "*weebexx.space*", "*slacks-us.space*", "*slack-im.online*", "*virtualbox-vm.org*", "*virtualbox-vm.us*", "*virtualbox-hardware.org*", "*blendar3d.accessdocman.com*", "*blender3ds-download.net*", "*blender3dorg.fras6899.odns.fr*", "*blenpder.org*", "*code.visualstudio.com.gammodo.com*", "*code-visual-lde.net*", "*rufus.ie.mekazg.com*", "*evilsoftware.pw*", "*pcapp.store*", "*clitrix.online*", "*ddockeers.space*", "*bassecanp.space*", "*onenole.website*", "*chainswaper.com*", "*tthunderbir.space*", "*wvwteamviewer.top*", "*zoomdowndesktop.store*", "*adobepresetforyou.us*", "*anydesk-access.com*")
```

# MS Defender
## IOC hunt
```
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in ("5.149.248.2", "5.149.254.27", "5.149.248.15", "5.149.254.84", "5.149.254.68", "79.141.160.2")
or RemoteUrl has_any ("ads-check.com", "down.software", "qtorrent.software", "winrar.software", "awesome-miner.software", "ccleaner.software", "mail-client.software", "top-wallet.software", "pdf-tools.software", "lightshot.software", "rufus-download.software", "downloaders.software", "any-desk.software", "down1.software", "download1.software", "vlc-media.software", "tor-browser.software", "rar-lab.software", "filezilla.space", "torrent-tools.software", "aimp.software", "archiver-7zip.software", "kmplayer.software", "notepad-editor.software", "amd-server2.life", "and-soft.online-application-form.com", "teamviewwer.tech", "nottepaddpluss.com", "geforse-drlvers.site", "download.winterlabs.click", "app1password.com", "app1password.com", "the1password.com", "docckeer.space", "weebexx.space", "slacks-us.space", "slack-im.online", "virtualbox-vm.org", "virtualbox-vm.us", "virtualbox-hardware.org", "blendar3d.accessdocman.com", "blender3ds-download.net", "blender3dorg.fras6899.odns.fr", "blenpder.org", "code.visualstudio.com.gammodo.com", "code-visual-lde.net", "rufus.ie.mekazg.com", "evilsoftware.pw", "pcapp.store", "clitrix.online", "ddockeers.space", "bassecanp.space", "onenole.website", "chainswaper.com", "tthunderbir.space", "wvwteamviewer.top", "zoomdowndesktop.store", "adobepresetforyou.us", "anydesk-access.com")
| summarize conCount = dcount(RemoteIP), Min = min(Timestamp), Max = max(Timestamp), IPs = make_set(RemoteIP), URLs = make_set(RemoteUrl) by DeviceName
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
TIP: You can use the dedicated hunt dashboards for these IOC hunts:
* [Domain Bulk Search](https://falcon.eu-1.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__domain_bulk)
* [IP Address Search](https://falcon.eu-1.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__ip)
## IOC hunt - Domains
```
search (DnsRequest OR SuspiciousDnsRequest) cid=*
              [| stats count
              | eval DomainName="ads-check.com down.software qtorrent.software winrar.software awesome-miner.software ccleaner.software mail-client.software top-wallet.software pdf-tools.software lightshot.software rufus-download.software downloaders.software any-desk.software down1.software download1.software vlc-media.software tor-browser.software rar-lab.software filezilla.space torrent-tools.software aimp.software archiver-7zip.software kmplayer.software notepad-editor.software amd-server2.life and-soft.online-application-form.com teamviewwer.tech nottepaddpluss.com geforse-drlvers.site download.winterlabs.click app1password.com app1password.com the1password.com docckeer.space weebexx.space slacks-us.space slack-im.online virtualbox-vm.org virtualbox-vm.us virtualbox-hardware.org blendar3d.accessdocman.com blender3ds-download.net blender3dorg.fras6899.odns.fr blenpder.org code.visualstudio.com.gammodo.com code-visual-lde.net rufus.ie.mekazg.com evilsoftware.pw pcapp.store clitrix.online ddockeers.space bassecanp.space onenole.website chainswaper.com tthunderbir.space wvwteamviewer.top zoomdowndesktop.store adobepresetforyou.us anydesk-access.com"
              | makemv DomainName delim=" "
              | fields DomainName ]
            | eval DomainName=lower(DomainName)
            | stats values(ComputerName) AS "Host Name", count AS Count, dc(ComputerName) AS "# of Hosts", last(ComputerName) AS "First Lookup By", min(_time) AS FirstLookupDate, latest(ComputerName) AS "Last Lookup By", max(_time) AS LastLookupDate by company, DomainName
            | eval WHOIS="Check Now"
            | eval "First Lookup Date"=FirstLookupDate
            | eval "Last Lookup Date"=LastLookupDate
            | convert ctime("First Lookup Date")
            | convert ctime("Last Lookup Date")
            | table company, DomainName, "Host Name", "# of Hosts", "First Lookup By", "First Lookup Date", "Last Lookup By", "Last Lookup Date", WHOIS, FirstLookupDate, LastLookupDate
            | rename DomainName AS "Domain Name"
```

## IOC hunt - IPs
```
search index=main event_simpleName=NetworkConnectIP4 cid=* (TERM("5.149.248.2") OR TERM("5.149.254.27") OR TERM("5.149.248.15") OR TERM("5.149.254.84") OR TERM("5.149.254.68") OR TERM("79.141.160.2"))
          | search LocalAddressIP4 IN (*) AND aip IN (*) AND RemoteAddressIP4 IN (5.149.248.2 5.149.254.27 5.149.248.15 5.149.254.84 5.149.254.68 79.141.160.2)
          | stats values(ComputerName) AS "Host Name", count AS Count, dc(ComputerName) AS "# of Hosts", last(ComputerName) AS "First Connection", min(_time) AS "First Connect Date", latest(ComputerName) AS "Last Connection", max(_time) AS "Last Connect Date", values(LocalAddressIP4) AS "Source IP", values(aip) AS "External IP" by company, RemoteAddressIP4  
          | convert ctime("First Connect Date") 
          | convert ctime("Last Connect Date") 
          | table company, "Source IP", RemoteAddressIP4, "External IP", "Host Name", "# of Hosts", "First Connection", "First Connect Date", "Last Connection", "Last Connect Date" 
          | rename RemoteAddressIP4 AS "Destination IP"
```