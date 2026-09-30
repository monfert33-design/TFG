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

### Versión 0.2 - Integración del Modelo de Lenguaje (LLM)
* **Objetivo de la versión:** Sustituir el análisis estático basado en expresiones regulares por un motor de inferencia con Inteligencia Artificial utilizando la API de Google Gemini (`gemini-2.5-flash`), permitiendo que el sistema interprete la evidencia cruda, evalúe la severidad y sugiera contramedidas operativas de forma autónoma.
* **Implementación en `main.py`:**
  * **Conexión con el SDK de Google GenAI:** Configuración del cliente oficial de Gemini mediante variables de entorno (`GEMINI_API_KEY`, `AI_MODEL`) para desacoplar las credenciales del código fuente.
  * **Ingeniería de Prompts Forense:** Definición de una instrucción de sistema (`SYSTEM_PROMPT_FORENSE`) con directivas estrictas para forzar al modelo a razonar como un perito DFIR y responder exclusivamente en un esquema JSON estructurado (`response_mime_type="application/json"`).
  * **Estandarización del Dictamen Pericial:** La respuesta del modelo normaliza campos como: `ataque_detectado`, `tipo_ataque`, `tecnica_mitre` (ej. `T1110.001 - Password Guessing`), `severidad`, `ip_atacante`, `usuario_objetivo`, `resumen_forense` y `contramedida_recomendada` (comando `iptables` sugerido).
  * **Nuevo Endpoint de Análisis Agéntico:** Creación de `POST /api/forensics/ai-analyze`, el cual automatiza la extracción de las últimas trazas de `/var/log/auth.log`, calcula su hash criptográfico SHA-256 para preservar la cadena de custodia y envía la evidencia cruda a Gemini para su triaje.
* **Pruebas y Resultados Obtenidos:**
  * Se lanzó un ataque de fuerza bruta SSH con Hydra desde Kali Linux (`192.168.56.10`) contra el servidor de pruebas.
  * A través de la documentación interactiva Swagger (`/docs`), se ejecutó una llamada de prueba contra `POST /api/forensics/ai-analyze`.
  * El modelo clasificó con precisión el ataque bajo la técnica MITRE `T1110.001`, asignó severidad alta, identificó correctamente la IP agresora y generó una propuesta de mitigación sintáctica válida para el firewall.
  * **Limitación detectada para siguientes versiones:** La extracción se realizaba mediante un recorte fijo de líneas (`tail -n 30`), lo que provocaba que una misma evidencia pudiera volver a analizarse si no había tráfico nuevo o que eventos pasados saturaran el prompt sin un control dinámico del estado de lectura.

### Versión 0.3 - Persistencia de Estado (Cursor Forense) y Optimización de Inferencia
* **Objetivo de la versión:** Resolver el reanálisis redundante de eventos pasados mediante la persistencia de lectura por deltas (*byte offsets*) y aumentar la profundidad técnica del dictamen generado por la IA.
* **Implementación en `main.py`:**
  * **Mecanismo de Cursor Forense (`.log_cursor.json`):** Implementación de las funciones `get_last_cursor()` y `save_cursor()` para rastrear la posición exacta en bytes dentro de `/var/log/auth.log`. El colector utiliza `seek()` para leer únicamente los deltas generados desde la última consulta.
  * **Manejo de Rotación de Logs (`logrotate`):** Detección de truncado cuando el tamaño actual del archivo es menor que el cursor guardado (`current_size < last_offset`), restableciendo el puntero a cero para no perder eventos tras una rotación.
  * **Control de Consumo de API:** Si no existen líneas nuevas en la ventana de tiempo evaluada (`has_new_logs == False`), el endpoint responde inmediatamente con `"sin_cambios": True`, evitando consultas innecesarias a Gemini y reduciendo latencia y coste.
  * **Endpoint Auxiliar de Mantenimiento:** Creación de `POST /api/forensics/reset-cursor` para permitir al analista sincronizar el puntero directamente con el final del archivo.
  * **Ampliación del Esquema JSON:** Se añadieron al prompt directivas para extraer métricas forenses cuantitativas (`intentos_estimados`, `rango_puertos_origen`, `frecuencia`) y una evaluación explícita de `impacto_potencial`.
* **Pruebas y Resultados Obtenidos:**
  * Al realizar consultas consecutivas sin ataques intermedios, el backend devolvió el estado sin cambios en milisegundos sin invocar al LLM.
  * Tras un nuevo barrido con Hydra desde Kali Linux, el sistema aisló exactamente el bloque de líneas nuevas, registrando la cadencia del ataque y sugiriendo la regla `iptables` específica sin arrastrar ruido histórico.
  * **Limitación detectada para siguientes versiones:** El análisis continuaba restringido de forma exclusiva a `/var/log/auth.log`, careciendo de visibilidad sobre eventos de red a nivel de firewall, actividad web o comandos del sistema.

### Versión 0.4 - Capacidades Agénticas (Tool Calling) y Remediación Activa (HITL)
* **Objetivo de la versión:** Transformar el analizador pasivo en un agente autónomo de respuesta a incidentes capaz de interactuar con el sistema operativo mediante llamadas a herramientas (*tool calling*) y habilitar la mitigación interactiva con supervisión humana.
* **Implementación en `main.py` y `agent_tools.py`:**
  * **Caja de Herramientas del Sistema (`agent_tools.py`):** Integración de funciones locales para inspeccionar sockets de red activos (`tool_listar_conexiones_red` mediante `ss`), examinar la tabla de procesos (`tool_inspeccionar_procesos` mediante `ps`) y consultar fragmentos complementarios de logs (`tool_leer_segmento_log`).
  * **Bucle de Razonamiento Agéntico:** Soporte para ejecución en bucle de herramientas en el endpoint `POST /api/forensics/ai-analyze`. Si el modelo detecta una agresión en los registros, puede solicitar información de sockets o procesos antes de emitir su dictamen pericial definitivo.
  * **Estructuración de Contramedidas:** El esquema de respuesta incorpora el objeto `accion_propuesta`, formalizando el tipo de acción (`BLOQUEAR_IP`), el identificador objetivo, el comando sugerido y la justificación técnica.
  * **Endpoint de Remediación (`POST /api/remediation/apply`):** Ejecución controlada de contramedidas en el sistema operativo mediante `subprocess`. Incluye comprobación previa para no duplicar reglas en `iptables`, protección contra el bloqueo accidental de la interfaz de bucle local (`127.0.0.1`) y respuesta con el estado del firewall.
  * **Control de Privilegios:** Configuración de reglas en `/etc/sudoers` para permitir la invocación de `iptables` sin requerir contraseña interactiva en el servidor.
* **Pruebas y Resultados Obtenidos:**
  * Se lanzó un ataque de fuerza bruta SSH con Hydra desde Kali Linux (`192.168.56.10`).
  * El agente detectó la agresión en `auth.log`, corroboró los sockets abiertos y propuso el bloqueo inmediato de la IP atacante.
  * Al pulsar el botón de mitigación en la interfaz de Avalonia UI, se ejecutó `iptables -I INPUT -s 192.168.56.10 -j DROP`.
  * La consola de Hydra en Kali quedó congelada inmediatamente con errores de *timeout*, y un sondeo con `nmap -p 22 192.168.56.20` reflejó el puerto como `filtered`. En Ubuntu, el comando `sudo iptables -L INPUT -v -n` constató el incremento en tiempo real de los paquetes descartados (*DROP*).
  * **Limitación detectada para siguientes versiones:** La ingesta continuaba limitada a eventos de autenticación (`auth.log`), sin procesar de forma nativa los registros de escaneo en el kernel ni anomalías del servidor web.

### Versión 0.5 - Telemetría Multicanal, Auditoría de Kernel (auditd) y Monitorización de Integridad (FIM)
* **Objetivo de la versión:** Superar la limitación del análisis exclusivo de autenticación (`auth.log`) evolucionando hacia un motor multicanal de espectro completo (red, web, sistema operativo, llamadas al núcleo e integridad de archivos), con capacidad de clasificar múltiples incidentes simultáneos de forma desacoplada y ejecutar remediaciones.
* **Implementación en `main.py` y Sistema Operativo:**
  * **Ingesta Multicanal Heterogénea:** Ampliación del diccionario `LOG_SOURCES` para monitorizar de manera coordinada cinco canales del sistema mediante punteros independientes (`offsets`):
    * `auth.log`: Abuso de `sudo`/`su`, manipulaciones de cuentas y fuerza bruta.
    * `kern.log`: Escaneos de puertos Nmap SYN interceptados por reglas de registro en `iptables`.
    * `nginx/access.log`: Ataques web de inyección SQL, *Path Traversal* / LFI y escaneo automatizado de rutas con Gobuster.
    * `syslog`: Detección de persistencia mediante modificaciones no autorizadas en tareas programadas (`cron`) y cierres forzados de servicios.
    * `audit/audit.log` (`auditd`): Trazas a nivel de llamadas al sistema (*syscalls*) para identificar ejecución de scripts y binarios en directorios temporales (`/tmp`, `/dev/shm`).
  * **Detección Activa de Evasión de Defensas (`T1070.002`):** Identificación automática de intentos de borrado o truncado intencionado de evidencias al comprobar variaciones anómalas en el puntero de lectura (`current_size < last_offset`), generando alertas de integridad prioritarias.
  * **Módulo de Integridad de Archivos (FIM):** Implementación de la función `check_file_integrity()` basada en el cálculo recurrente de hashes criptográficos SHA-256 (`.fim_hashes.json`) sobre binarios y configuraciones sensibles (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/bin/ps`, `/bin/ls`) para alertar ante manipulaciones locales o *trojaning*.
  * **Desacoplamiento de Incidentes Concurrentes:** Rediseño estructural de la respuesta de Gemini para emitir un listado independiente de incidentes (`"incidentes": [...]`), permitiendo que eventos simultáneos de distinta naturaleza (por ejemplo, un ataque web y un escaneo de red concurrente) no se mezclen en un único dictamen.
  * **Ampliación de Remediación HITL (`MATAR_PROCESO`):** Extensión del endpoint `/api/remediation/apply` con soporte para neutralizar sesiones activas de C2 / Shells Reversas mediante `kill -9 <PID>` con comprobaciones de seguridad sobre procesos reservados del sistema.
* **Pruebas y Resultados Obtenidos:**
  * **Frente Web:** Un ataque con inyecciones SQL y sondeos con Gobuster desde Kali Linux (`192.168.56.10`) se catalogó bajo la técnica `T1190` a través del canal Nginx.
  * **Persistencia y Shell Reversa:** La inyección de una tarea en `crontab` y la posterior apertura de una reverse shell hacia Kali mediante sockets Python fue catalogada con severidad crítica (`T1053.003`, `T1059.004`), habilitando la contramedida de terminación de proceso.
  * **Evasión y Manipulación FIM:** Al forzar el truncado a 0 bytes de los registros de Nginx (`truncate -s 0`), el sistema identificó de inmediato la maniobra evasiva (`T1070.002`), sugiriendo la protección de inmutabilidad (`chattr +a`).
