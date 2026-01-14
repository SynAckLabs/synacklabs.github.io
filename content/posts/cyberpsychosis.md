---
title: "Cyberpsychosis (Easy)"
date: 2026-01-13
author: "Khaled"
tags: ["Reversing", "RootKit", "Ghidra"]
categories: ["Challenge"]
slug: "cyberpsychosis"
draft: false
---


_“Malicious actors have infiltrated our systems and we believe they've implanted a custom rootkit. Can you disarm the rootkit and find the hidden data?”_


PASO 1: Descomprimir y analizar el archivo


Cuando descomprimos el .zip que nos facilitan vemos que se trata de un archivo .ko (diamorphine.ko)


Si hacemos una busqueda en google de este tipo de archivo vemos que se trata de un “Kernel Object”; un módulo de kernel cargable en sistemas Linux.


![Imagen del post](/images/notion/2e7888fa-f353-80d8-bc93-d34125670230.png)


Realizamos una busqueda de diamorphine y podemos ver que se trata de un LKM (Loadable Kernel Module) rootkit para kernels de Linux.


PASO 2: Ingeniería inversa en el binario

    1. Cargar el binario a Ghidra para realizar un analisis mas profundo.
    2. Ver los strings por si podemos sacar alguna pista para ver de que trata el binario

        ![Imagen del post](/images/notion/2e7888fa-f353-806a-bd96-e62e5dc1f964.png)


        Los strings confirman que se trata del rootkit Diamorphine.


PASO 3: Entendiendo el comportamiento del binario 

1. El objetivo de este challenge es enontrar el kill switch para desactivar el rootkit para eso debemos entender como funciona el rootkit.
2. Segun el README de [https://github.com/m0nad/Diamorphine](https://github.com/m0nad/Diamorphine) actua de la siguiente manera:
    - `When loaded, the module starts invisible;`
    - `Hide/unhide any process by sending a signal 31;`
    - `Sending a signal 63(to any pid) makes the module become (in)visible;`
    - `Sending a signal 64(to any pid) makes the given user become root;`
3. Pero para desarmar el root hay que realizar lo siguiente:

    ```bash
    The module starts invisible, to remove you need to make it visible
    kill -63 0
    Then remove the module(as root)
    rmmod diamorphine
    ```


    El módulo empieza estando invisible, hay que hacerlo visible para luego eliminarlo siendo root. Vamos a ello!


PASO 4: Desactivar el RootKit

1. Nos conectamos a la IP+puerto con nc:

    `nc <IP> <Puerto>`

2. Usaremos los pasos que hemos visto en el README; Hacerlo invisible y eliminarlo

![Imagen del post](/images/notion/2e7888fa-f353-803f-8708-f3c63321d4bc.png)


!! Después de intentarlo nos salta un crash (kernel panic) demostrando que ha podido haver algún cambio en el código de diamorphine. !!


PASO 5: Volvemos a la Ingeniería Inversa para revisar la modificación 

    1. Entramos en la función _**hacked_kill()**_ y podemos observar que hay una funcionalidad que es la que hace que deje ser invisible pero el número esta en hex. Click derecho y lo pasamos a decimal.

        ![Imagen del post](/images/notion/2e7888fa-f353-8039-a17b-dcbb3a555f30.png)


        ![Imagen del post](/images/notion/2e7888fa-f353-8032-a3d3-ee359b65f260.png)


        El número mágico es el 46, así que lo probamos.

        1. Hacemos visible el módulo y nos damos permisos de root con el código que nos decía el README (-64).

            ![Imagen del post](/images/notion/2e7888fa-f353-80f7-b652-cac6bfa58d3d.png)


PASO FINAL: Buscar la flag

1. Sabiendo que HTB esconde sus flags en archivos .txt, hacemos una busqueda masiva en todos los directorios.

    ![Imagen del post](/images/notion/2e7888fa-f353-80c4-80f2-e71d70b353b7.png)

2. Solo queda hacer cat de la flag y ya lo tenemos!!

    ![Imagen del post](/images/notion/2e7888fa-f353-80e2-9714-d4c1a067b6c7.png)

