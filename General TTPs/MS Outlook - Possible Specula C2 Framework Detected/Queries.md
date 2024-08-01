# Splunk
## TTP hunt
```
TODO
```

# MS Defender
## TTP hunt
```
DeviceRegistryEvents 
| where RegistryValueName == "URL"
and RegistryKey has_any ("Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Inbox", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Calendar", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Contacts", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Deleted Items", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Drafts", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Journal", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Junk E-mail", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Notes", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Outbox", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\RSS", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Sent Mail", "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\Tasks", "Software\\Microsoft\\Office\\16.0\\Outlook\\Today", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Inbox", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Calendar", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Contacts", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Deleted Items", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Drafts", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Journal", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Junk E-mail", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Notes", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Outbox", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\RSS", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Sent Mail", "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\Tasks", "Software\\Microsoft\\Office\\15.0\\Outlook\\Today", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Inbox", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Calendar", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Contacts", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Deleted Items", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Drafts", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Journal", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Junk E-mail", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Notes", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Outbox", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\RSS", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Sent Mail", "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\Tasks", "Software\\Microsoft\\Office\\14.0\\Outlook\\Today")
```

# CrowdStrike
## TTP hunt
```
Not possible due to limitations on registry events.
```