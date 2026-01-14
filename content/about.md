---
title: "Whoweare"
hidemeta: true
layout: "about"
---

## root@SynAckLabs:~$ id
<div class="typing-container">
  <p class="typing-effect">uid=0(root) gid=0(root) groups=0(root) context=sys_u:system_r:init_t:s0</p>
</div>

---

### >_ Misión

**SynAckLabs** es un espacio de investigación y aprendizaje donde colisionan dos mundos: la ofensiva (**Red Team**) y la defensiva (**Blue Team**). 

Nuestro objetivo no es solo romper cosas, sino entender cómo se rompen para protegerlas mejor (o romperlas con más estilo).

---

### >_ El Equipo

<div style="display: flex; align-items: center; margin-top: 1.5em; margin-bottom: 0.5em;">
  <h4 class="hacker-glitch" style="margin: 0; margin-right: 10px; cursor: default;">Ismael Laya Martínez</h4>
  
  <a href="https://www.linkedin.com/in/ismael-laya/" target="_blank" style="display: flex; align-items: center;">
    <img src="https://content.linkedin.com/content/dam/me/business/en-us/amp/brand-site/v2/bg/LI-Bug.svg.original.svg" alt="LinkedIn" style="height: 24px; width: auto;">
  </a>
</div>

<div style="display: flex; align-items: center; margin-top: 1em; margin-bottom: 0.5em;">
  <h4 class="hacker-glitch" style="margin: 0; margin-right: 10px; cursor: default;">Khaled El Modden</h4>
  
  <a href="https://www.linkedin.com/in/khaled-e-4a28b1141/" target="_blank" style="display: flex; align-items: center;">
    <img src="https://content.linkedin.com/content/dam/me/business/en-us/amp/brand-site/v2/bg/LI-Bug.svg.original.svg" alt="LinkedIn" style="height: 24px; width: auto;">
  </a>
</div>

---

<style>
  /* 1. ANIMACIÓN DE ESCRITURA (Typing) */
  .typing-container {
    display: inline-block;
    background-color: #3f002e00; /* Fondo oscuro para resaltar */
    padding: 2px 5px;
    border-radius: 4px;
    font-family: monospace;
  }
  
  .typing-effect {
    border-right: 2px solid #ff00ae; /* Cursor verde */
    white-space: nowrap;
    overflow: hidden;
    margin: 0;
    width: 0; /* Empieza oculto */
    color: #cccccc; /* Color del texto */
    animation: typing 2.5s steps(40) forwards, blink 0.75s step-end infinite;
  }

  /* El cursor parpadea */
  @keyframes blink {
    from, to { border-color: transparent }
    50% { border-color: #e100ff; }
  }

  /* Las letras aparecen */
  @keyframes typing {
    from { width: 0 }
    to { width: 100% }
  }

  /* 2. ANIMACIÓN GLITCH (Para los nombres) */
  .hacker-glitch:hover {
    animation: glitch 0.3s cubic-bezier(.25, .46, .45, .94) both infinite;
    color: #ff00ff; /* Cambia a rojo neón al pasar el ratón */
    text-shadow: 2px 2px #c444ff; /* Sombra verde */
  }

  @keyframes glitch {
    0% { transform: translate(0); }
    20% { transform: translate(-2px, 2px); }
    40% { transform: translate(-2px, -2px); }
    60% { transform: translate(2px, 2px); }
    80% { transform: translate(2px, -2px); }
    100% { transform: translate(0); }
  }
</style>