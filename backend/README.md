# Backend - Servidor de Telemetría, Motor DFIR y Remediación

En este directorio se aloja el núcleo de la plataforma defensiva. El backend actúa como la capa intermedia entre el sistema operativo Ubuntu Server (recolección de telemetría y ejecución de defensas), el modelo de lenguaje de Google Gemini (análisis pericial y clasificación de amenazas) y el panel de control en Avalonia UI (consumo de eventos y autorización de contramedidas).

---

## Descripción del Módulo

El backend está desarrollado sobre **FastAPI** en Python 3.12 y cumple tres funciones dentro de la arquitectura:

1. **Ingesta y Filtrado Multicanal de Telemetría:** 
   Monitorea de forma no intrusiva los registros del servidor. Utiliza punteros de lectura (*offsets*) almacenados en disco para procesar únicamente las líneas nuevas generadas desde el último ciclo, evitando lecturas redundantes o saturación de datos.

2. **Inferencia Agéntica y Peritaje Forense:** 
   Empaqueta los deltas de telemetría, calcula un sello criptográfico SHA-256 para preservar la integridad de la evidencia y consulta a la API de **Google Gemini**. El modelo evalúa los datos y genera un reporte estructurado en formato JSON, separando incidentes concurrentes, identificando la técnica MITRE ATT&CK correspondiente y sugiriendo una contramedida operativa.

3. **Remediación Activa Supervisada (Human-in-the-Loop):** 
   Expone endpoints seguros para ejecutar contramedidas autorizadas por el analista en el sistema operativo mediante llamadas de sistema (`subprocess`), tales como bloqueos automáticos en el firewall (`iptables`) o terminación forzada de procesos maliciosos (`kill -9`).

---

## Estructura de Ficheros

* `main.py`: Punto de entrada de la aplicación FastAPI. Contiene los endpoints REST, el recolector de logs, la lógica de comprobación de integridad (FIM) y el cliente de inferencia de Gemini.
* `agent_tools.py`: Definición de herramientas de inspección del sistema local (lectura de sockets abiertos, procesos activos o fragmentos de logs) disponibles para el agente.
* `.env`: Archivo de configuración local para variables de entorno (claves de API, modelo seleccionado y puertos). Excluido de Git.
* `.log_cursor.json`: Archivo de estado temporal que almacena los bytes leídos de cada fichero de log para el control de deltas. Excluido de Git.
* `.fim_hashes.json`: Registro de hashes SHA-256 de los ficheros críticos del sistema para la detección de modificaciones no autorizadas. Excluido de Git.

---

## Requisitos y Puesta en Marcha

### Dependencias Principales
* Python 3.12+ con entorno virtual (`venv`).
* Paquetes de Python: `fastapi`, `uvicorn`, `python-dotenv`, `google-genai`, `pydantic`.
* Servicios del sistema: `nginx`, `iptables`, `auditd`.

### Ejecución del Servicio
Desde este directorio con el entorno virtual activo(la ruta va en funcion de donde tu tengas guardado el repositorio):

```bash
sudo /home/(Tu usuario)/TFG/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
---

## Versiones del proyecto:

### Versión 0.1 - Prueba de Concepto Inicial y Sellado Criptográfico
* **Objetivo de la versión:** Validar la viabilidad del pipeline básico de adquisición forense y comprobar la comunicación entre el entorno de logs de Ubuntu Server y una API REST accesible desde red local.
* **Implementación en `main.py`:**
  * Creación del servidor base utilizando **FastAPI**.
  * Definición de un modelo de datos estructurado (`ForensicEvidence`) con **Pydantic** para normalizar los campos clave de un incidente: identificación de caso (`case_id`), marcas de tiempo de inicio y fin, IP del atacante, usuario objetivo y mapeo contra MITRE ATT&CK (`T1110.001 - Password Guessing`).
  * Implementación de la función `parse_auth_log()` mediante expresiones regulares (`re.compile`) para extraer eventos de autenticación fallida procedentes del servicio `sshd` en `/var/log/auth.log`.
  * Incorporación del sellado criptográfico de la evidencia en crudo calculando el hash **SHA-256** del bloque de líneas extraídas, sentando las bases de la cadena de custodia digital.
  * Publicación del primer endpoint operativo: `GET /api/forensics/analyze`.
* **Pruebas y Resultados Obtenidos:**
  * Se lanzó un ataque de fuerza bruta SSH controlado desde la máquina atacante Kali Linux (`192.168.56.10`) contra el servidor de pruebas (`192.168.56.20`).
  * El endpoint devolvió satisfactoriamente el objeto JSON estructurado con el recuento exacto de intentos fallidos, identificó la IP origen del atacante, el usuario víctima (`root`) y adjuntó una muestra de las últimas trazas analizadas junto a su correspondiente firma SHA-256.
  * **Limitación detectada para siguientes versiones:** En esta primera prueba el archivo de logs se leía completo desde el inicio y de forma estática en cada petición, sin persistencia de lectura ni capacidad de análisis con modelos de lenguaje.
