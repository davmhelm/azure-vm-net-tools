# "Enabled ICMPv4 Windows Firewall Rule - Allow Ping on target VM
Set-NetfirewallRule -Name FPS-ICMP4-ERQ-In -Enable True -Profile Any

# Systinternals Psping 
Invoke-WebRequest -Uri "https://live.sysinternals.com/psping.exe" -OutFile "$env:windir\system32\psping.exe" -UseBasicParsing

# TCPing
Invoke-WebRequest -Uri "https://download.elifulkerson.com/files/tcping/0.39/x64/tcping64.exe" -OutFile "$env:windir\system32\tcping.exe" -UseBasicParsing

# Network Monitor using silent install
Invoke-WebRequest -Uri https://download.microsoft.com/download/7/1/0/7105C7FF-768E-4472-AFD5-F29108D1E383/NM34_x64.exe -OutFile "$env:windir\temp\NM34_x64.exe" -UseBasicParsing
cmd /c "$env:windir\temp\NM34_x64.exe /q"

# NTTTCP - Reference: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-bandwidth-testing
Invoke-WebRequest -Uri "https://github.com/microsoft/ntttcp/releases/download/v5.35/NTttcp.exe" -Outfile "$env:windir\system32\NTttcp.exe" -UseBasicParsing

# Wireshark using silent install -- requires npcap library, which must be interactively installed per free license terms
Invoke-WebRequest -Uri "https://www.wireshark.org/wireshark-pad.xml" -OutFile "$env:windir\temp\wireshark-pad.xml" -UseBasicParsing
$wiresharkpad = [xml](Get-Content -Path "$env:windir\temp\wireshark-pad.xml")
Invoke-WebRequest -Uri ($wiresharkpad.XML_DIZ_INFO.Web_Info.Download_Urls.Primary_Download_URL) -OutFile "$env:windir\temp\wireshark-latest.exe" -UseBasicParsing
cmd /c "$env:windir\temp\wireshark-latest.exe /S"

# nmap using RunOnce interactive install
Invoke-WebRequest -Uri "https://nmap.org/dist/nmap-7.92-setup.exe" -OutFile "$env:windir\temp\nmap-setup.exe" -UseBasicParsing
# Add one-time installer to next login
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name '!nettools_1_nmap' -PropertyType String -Value "$env:windir\temp\nmap-setup.exe" -Force

# npcap using RunOnce interactive install
Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.70.exe" -OutFile "$env:windir\temp\npcap-setup.exe" -UseBasicParsing
# Add one-time installer to next login
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name '!nettools_2_npcap' -PropertyType String -Value "$env:windir\temp\npcap-setup.exe" -Force

# Enable IIS for testing HTTP/TCP
Install-WindowsFeature -name Web-Server -IncludeManagementTools
Set-Content -Path "C:\inetpub\wwwroot\index.html" -Value $env:COMPUTERNAME -Encoding utf8
Add-Content -Path "C:\inetpub\wwwroot\index.html" -Value (Get-ComputerInfo -Property "OsName").OsName -Encoding utf8
