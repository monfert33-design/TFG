#Plataforma DFIR & Purple Teaming con IA Generativa

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20(Python%203.12)-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Avalonia UI](https://img.shields.io/badge/Frontend-Avalonia%20UI%20(.NET%208)-purple?logo=dotnet)](https://avaloniaui.net/)
[![Google Gemini](https://img.shields.io/badge/LLM-Gemini%202.5%20Flash-orange?logo=google)](https://ai.google.dev/)
[![Security Standards](https://img.shields.io/badge/Mapping-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)

Trabajo de Fin de Grado (TFG) desarrollado por **Marcos García Gómez**.

---

##Descripción del Proyecto:

Este proyecto consiste en el diseño e implementación de una plataforma de ciberseguridad orientada a **DFIR** (*Digital Forensics and Incident Response*) y ejercicios de **Purple Teaming**. 

El sistema monitoriza en tiempo real los eventos y registros de un servidor Linux, procesa la telemetría generada y utiliza un modelo de lenguaje (LLM) configurado como agente autónomo. El agente se encarga de:

1. **Analizar la telemetría:** Interpretar los registros generados por múltiples fuentes del sistema para identificar patrones anómalos.
2. **Clasificar los incidentes:** Mapear cada agresión contra las tácticas y técnicas del marco estándar **MITRE ATT&CK**.
3. **Generar un dictamen pericial:** Explicar el origen, los parámetros del ataque y su nivel de severidad.
4. **Proponer y ejecutar contramedidas (Human-in-the-Loop):** Sugerir acciones de mitigación inmediatas (como bloqueos en el firewall o terminación de procesos maliciosos) que el analista puede autorizar desde el panel de control.
5. **Perspectiva Purple Team:** Evaluar de forma cruzada la efectividad de los vectores de ataque simulados frente a la capacidad de detección y respuesta de los mecanismos defensivos.
---

##Arquitectura General del Sistema

```text
+-----------------------------------------------------------------------------------------+
|                                    RED PRIVADA HOST-ONLY                                |
|                                       (192.168.56.0/24)                                 |
+-----------------------------------------------------------------------------------------+
            |                                                               |
            v                                                               v
  +--------------------+                                         +---------------------+
  |   KALI LINUX       |                                         |    UBUNTU SERVER    |
  |   (Red Team)       |                                         |     (Blue Team)     |
  |                    |                                         |                     |
  |  192.168.56.10     | ======[ Vectores de Intrusión ]=======> |    192.168.56.20    |
  |  - Nmap (SYN)      |                                         |                     |
  |  - Hydra (SSH)     |                                         |  +---------------+  |
  |  - Gobuster/LFI    |                                         |  | Daemon Nginx  |  |
  |  - Reverse Shells  |                                         |  | OpenSSH Server|  |
  +--------------------+                                         |  | auditd / FIM  |  |
                                                                 |  +---------------+  |
                                                                 |         |           |
                                                                 |  [ Telemetría Logs ]|
                                                                 |         v           |
                                                                 |  +---------------+  |
                                                                 |  | Backend DFIR  |  |
                                                                 |  |   (FastAPI)   |  |
                                                                 |  +---------------+  |
                                                                 +----------|----------+
                                                                            |
                                               API REST (HTTP/JSON)         | 192.168.56.20:8000
                                                                            v
+-----------------------------------------------------------------------------------------+
| HOST FÍSICO / ESTACIÓN DE ANÁLISIS                                                      |
|                                                                                         |
|  +-------------------------------------+      +--------------------------------------+  |
|  |       AVALONIA UI DASHBOARD         |      |           GOOGLE GEMINI API          |  |
|  |      (.NET 8 / C# Cross-Platform)   |      |                                      |  |
|  |  - Triage en tiempo real            | <==> |  - Razonamiento agéntico             |  |
|  |  - Mitigación HITL interactiva      |      |  - Extracción de entidades           |  |
|  |  - Integridad SHA-256 de evidencias |      |  - Salida estructurada JSON          |  |
|  +-------------------------------------+      +--------------------------------------+  |
+-----------------------------------------------------------------------------------------+

### Componentes y Entorno de Red

* **Red Privada Virtual (Host-Only):** Segmento de red `192.168.56.0/24` desplegado sobre Oracle VirtualBox, permitiendo aislar el tráfico de prueba de la red local física e Internet.
* **Máquina Objetivo y Defensiva (`192.168.56.20` - Ubuntu Server 24.04 LTS):**
  * Aloja el servidor web objetivo y los servicios bajo monitorización.
  * Ejecuta el backend en Python encargado de recolectar logs, calcular hashes de integridad forense y comunicarse con la IA.
* **Máquina Atacante (`192.168.56.10` - Kali Linux):**
  * Actúa como origen del tráfico malicioso para validar las capacidades de detección frente a herramientas comunes de auditoría y explotación.
* **Estación de Monitorización (Sistema Anfitrión):**
  * Ejecuta la interfaz de usuario de escritorio para supervisar las alertas, revisar los dictámenes de la IA y aplicar las contramedidas.

---

## Tecnologías Utilizadas

### Backend y Captura de Evidencias
* **Python 3.12:** Lenguaje principal utilizado para orquestar la ingesta de telemetría, el parseo de registros y la lógica de remediación.
* **FastAPI & Uvicorn:** Framework asíncrono de alto rendimiento para exponer los endpoints de análisis forense y ejecución de acciones.
* **Linux Audit Framework (`auditd`):** Subsistema de auditoría del kernel para registrar eventos a nivel de llamadas al sistema (*syscalls*), como ejecuciones en `/tmp` o modificaciones de binarios.
* **Gestor de Integridad (FIM):** Algoritmos basados en SHA-256 para detectar alteraciones no autorizadas en archivos sensibles del sistema (`/etc/passwd`, `/etc/shadow`, etc.).
* **Iptables & Subprocess:** Herramientas nativas del sistema operativo utilizadas para aplicar reglas de filtrado en caliente y mitigación de procesos hostiles.

### Inteligencia Artificial
* **Google Gemini API:** Modelo multimodal utilizado como motor de inferencia analítica. Proporciona una ventana de contexto amplia para procesar bloques de logs en crudo, minimiza la latencia de respuesta y permite estructurar la salida directamente en esquemas JSON estandarizados.

### Frontend
* **Avalonia UI (.NET / C#):** Framework de interfaz gráfica multiplataforma implementado bajo el patrón MVVM (*Model-View-ViewModel*), encargado de mostrar el histórico de alertas, los datos de integridad criptográfica y los botones de mitigación interactiva.

---

## 📂 Estructura del Repositorio

```text
├── backend/            # API en FastAPI, gestión de cursores, FIM y conexión con Gemini
├── frontend/           # Solución Avalonia UI en C# (Vistas, ViewModels y Servicios)
├── scripts/            # Scripts de ataque y pruebas de simulación en Kali Linux
├── docs/               # Diagramas, especificaciones técnicas y anexos para la memoria
├── .gitignore          # Exclusión de credenciales, entornos virtuales y temporales
└── README.md           # Presentación general del proyecto
