# Frontend - Panel de Control SOC & Triaje DFIR Asistido por IA

En este directorio se aloja el cliente de escritorio y estación de supervisión de la plataforma defensiva. Desarrollado con **Avalonia UI** sobre **.NET 9 / C#**, proporciona una interfaz gráfica moderna y multiplataforma para monitorizar en tiempo real las alertas de seguridad generadas por el backend, inspeccionar evidencias forenses y autorizar contramedidas.

---

## Descripción del Módulo

La aplicación de interfaz de usuario se implementa siguiendo el patrón arquitectónico **MVVM (Model-View-ViewModel)**, separando la lógica de presentación, la gestión de estados y la comunicación asíncrona por red:

1. **Gestión Reactiva de Incidentes (MVVM):**  
   Utiliza `CommunityToolkit.Mvvm` para enlazar datos bidireccionalmente entre los modelos periciales y las vistas AXAML. Permite seleccionar casos del histórico, actualizar el panel de inspección al instante y filtrar eventos dinámicamente mediante cuadros de búsqueda.

2. **Consumo Asíncrono de la API Forense:**  
   A través de un servicio HTTP desacoplado (`ForensicApiService`), la aplicación realiza peticiones contra el backend en FastAPI (`http://192.168.56.20:8000`). Soporta tanto el análisis manual bajo demanda (**Forzar Análisis**) como un ciclo de monitorización desatendida (**Auto-Scan**) configurable.

3. **Supervisión de Cadena de Custodia:**  
   Expone de manera destacada el sello criptográfico **SHA-256** de la evidencia cruda adquirida, el identificador único del caso (`CASE-YYYYMMDD-HHMMSS`) y el mapeo estandarizado contra el marco **MITRE ATT&CK**.

4. **Defensa Activa y Mitigación Interactiva (HITL):**  
   Cuando la IA dictamina que un incidente requiere respuesta técnica, la interfaz extrae la propuesta de contramedida, la resalta en una barra de estado contextual y habilita el botón de acción (*Ejecutar Bloqueo / Remediación*) para aplicar la regla en el servidor remoto tras la confirmación del analista.

---

## Estructura Visual de la Interfaz

La ventana principal se organiza en tres zonas de trabajo funcionales:

```text
+-------------------------------------------------------------------------------------------------------------+
| [=] DFIR SOC Dashboard - Incident Triage                                                           [-] [x] |
+-------------------------------------------------------------------------------------------------------------+
| [🔍 Filtrar por IP, caso, severidad...]                           [Auto-Scan: False] [Forzar Análisis]     |
+-------------------+-----------------------------------------------------------------------------------------+
| [H]               | CASE-20260929-173149                                                           [CRÍTICA]|
|                   | Fecha de adquisición: 2026-09-29 17:31:49 UTC                                           |
| [*] Histórico     +--------------------------------------------+--------------------------------------------+
|     de Incidentes | IP ATACANTE                                | TÉCNICA MITRE ATT&CK                       |
|                   | 192.168.56.10                              | T1053.003, T1059.004                       |
| +---------------+ +--------------------------------------------+--------------------------------------------+
| |Persistencia   | | INTEGRIDAD FORENSE (SHA-256 EVIDENCIA CRUDA)                                            |
| |Cron / Shell C2| | b92202e2662ab0bd3a2f40a40c99a881eebcc7a8cc7052fe6e4f252bd599ab40                        |
| |192.168.56.10  | +-----------------------------------------------------------------------------------------+
| |CRÍTICA        | | DICTAMEN PERICIAL (GENERADO POR IA)                                                     |
| +---------------+ | Se detecta una tarea programada (cron job) ejecutándose bajo el usuario 'marcos' que    |
| |Fuerza Bruta   | | intenta establecer una shell reversa persistente hacia la IP 192.168.56.10:4444...      |
| |SSH            | |                                                                                         |
| |192.168.56.10  | |                                                                                         |
| |ALTA           | |                                                                                         |
| +---------------+ |                                                                                         |
| |Evasión Logs   | |                                                                                         |
| |Local / ALTA   | |                                                                                         |
+-------------------+-----------------------------------------------------------------------------------------+
| (•) ¡ALERTA NUEVA! Contramedida: iptables -I INPUT -s 192.168.56.10 -j DROP             [Ejecutar Bloqueo]  |
+-------------------------------------------------------------------------------------------------------------+

```

---

## 📂 Organización del Código en la Solución

```text
frontend/
├── Models/
│   └── ForensicCase.cs         # Esquemas de datos (casos, dictamen de IA, contramedidas y resultados)
├── Services/
│   └── ForensicsApiService.cs  # Cliente HTTP asíncrono para el consumo de la API de FastAPI
├── ViewModels/
│   ├── ViewModelBase.cs        # Clase base con soporte para propiedades observables
│   └── MainViewModel.cs        # Lógica de presentación, colecciones, filtrado y comandos de mitigación
├── Views/
│   ├── MainWindow.axaml        # Definición declarativa de la interfaz (XAML/Estilos oscuros SOC)
│   └── MainWindow.axaml.cs     # Code-behind asociado a la ventana principal
├── App.axaml                   # Recursos globales de estilos y temas de Avalonia
├── App.axaml.cs                # Inicialización de la aplicación e inyección del ViewModel principal
└── TuProyecto.csproj           # Configuración de dependencias de .NET y paquetes NuGet

```

---

## Requisitos y Compilación en Windows

### Requisitos Previos

* Windows 10 u 11 (64-bit).
* **.NET 8.0 SDK** (o superior).
* **Visual Studio 2022** (con la carga de trabajo *Desarrollo de escritorio de .NET*) o **VS Code** con la extensión oficial de C# Dev Kit.
* Extensión recomendada: **Avalonia for Visual Studio 2022** (para previsualización XAML).

### Compilación y Ejecución desde Terminal (PowerShell)

1. Entra al directorio de la solución:
```powershell
cd frontend

```

2. Restaura los paquetes NuGet necesarios:
```powershell
dotnet restore

```

3. Compila el proyecto:
```powershell
dotnet build

```

4. Lanza la aplicación:
```powershell
dotnet run

```

---

##  Registro de Versiones (Changelog)

---

### Versión 0.1 - Dashboard SOC Inicial con Enlace Reactivo y Mitigación HITL

* **Objetivo de la versión:** Crear una aplicación de escritorio nativa orientada a centros de operaciones de seguridad (SOC) que consuma la telemetría del backend, permita la navegación fluida entre incidentes históricos y ejecute respuestas activas autorizadas por el analista.
* **Implementación del Sistema:**
  * **Estructura MVVM con CommunityToolkit.Mvvm:**
    * `Models/ForensicCase.cs`: Implementación de los modelos que deserializan la respuesta JSON de FastAPI (`ForensicCaseResponse`, `ExpertOpinion`, `RemediationAction` y `RemediationResult`).
    * `Services/ForensicsApiService.cs`: Implementación de un cliente `HttpClient` singleton con configuración de *timeout* extendida (30 segundos) para tolerar el tiempo de inferencia de la IA. Implementa los métodos `AnalyzeIncidentAsync()` para la consulta de deltas y `ApplyRemediationAsync()` para remitir las órdenes de contramedida.
    * `ViewModels/MainViewModel.cs`: Gestión del estado global con listas observables (`ObservableCollection<ForensicCaseResponse>`), control del caso activo seleccionado (`SelectedCase`), comandos asíncronos para forzar análisis y alternancia de sondeo automático mediante temporizadores de fondo.

  * **Diseño Visual e Interfaz de Usuario (`Views/MainWindow.axaml`):**
    * Paleta de colores en tema oscuro (fondos `#0D1117`, paneles `#161B22`, acentos azules `#0078D4` y badges de severidad por color: rojo para Crítica, naranja para Alta, verde para Baja).
    * Barra lateral con listado de tarjetas históricas seleccionables con información resumida de cada vector.
    * Panel central de detalles con visualización destacada del hash SHA-256 en formato monoespaciado y cuadro pericial con la explicación generada por Gemini.
    * Barra inferior de estado para notificaciones en caliente y botón dinámico **Ejecutar Bloqueo**.

* **Pruebas y Resultados Obtenidos:**
  * Se validó la comunicación entre la máquina anfitriona Windows (`192.168.56.1`) y el servidor Ubuntu (`192.168.56.20:8000`).
  * La aplicación recibió y renderizó correctamente escenarios combinados de fuerza bruta SSH, escaneos Nmap, fuzzing web con Gobuster, manipulación de `cron` y persistencia con shells reversas.
  * Al pulsar el botón de mitigación ante un ataque clasificado, el frontend envió la orden de bloqueo (`iptables`) al backend, actualizó la etiqueta de estado a `[DEFENSA ACTIVA]` y deshabilitó el botón.

---

### Versión 0.2 - Persistencia Local, Diálogos HITL Modales, Arquitectura Multi-Vista y Panel Analítico

* **Objetivo de la versión:** Desacoplar el frontend del proveedor de IA para garantizar neutralidad del LLM, añadir persistencia local para auditoría forense, reforzar los mecanismos de Human-in-the-Loop mediante modales de autorización interactivos y proporcionar un cuadro de mandos analítico (Estadísticas Globales) sin salir de la aplicación.
* **Implementación del Sistema:**
  * **Abstracción y Neutralidad del Motor LLM:**
    * `Models/SystemHealth.cs` y Diagnóstico: Se refactorizaron las definiciones dependientes de proveedor (`gemini_ai`) sustituyéndolas por esquemas agnósticos (`llm_engine`), permitiendo alternar el modelo en el backend sin provocar fallos de serialización o compilación en el cliente.
    * Ciclo de Vida de Arranque (`Views/SplashWindow.axaml.cs`): Reasignación segura de `Application.Current.MainWindow` para evitar excepciones de ventanas huérfanas (`closed owner`) al transicionar desde la pantalla de diagnóstico al panel operativo.

  * **Persistencia Local y Registro Forense en Disco:**
    * `Services/StorageService.cs`: Creación de un servicio de almacenamiento local que gestiona archivos JSON en el directorio de ejecución (`Data/`):
      * `incident_history.json`: Persistencia estructurada de todo el historial de alertas clasificadas para su recuperación entre sesiones.
      * `remediation_history.json`: Cuaderno de bitácora y trazabilidad de contramedidas ejecutadas (comando exacto aplicado, objetivo, justificación forense y respuesta del servidor).
    * `Models/RemediationAuditRecord.cs`: Esquema de datos para la auditoría inmutable de acciones de remediación.
    * Estructura de los archivos generados:

    ```text
    frontend/Data/
    ├── incident_history.json       # Persistencia local de todas las alertas clasificadas
    └── remediation_history.json    # Registro de auditoría de contramedidas aplicadas (HITL)
    ```

  * **Segmentación Temporal de Alertas (< 2 Horas vs. Histórico):**
    * Reorganización en `ViewModels/MainViewModel.cs`: División del flujo de incidentes en dos colecciones observables diferenciadas:
      * `CurrentSessionCases`: Alertas recibidas en tiempo real o con antigüedad inferior a 2 horas.
      * `ArchivedCases`: Incidentes con antigüedad ≥ 2 horas o provenientes de sesiones previas, asegurando un triaje despejado para el analista en turno.
    * Evaluación Dinámica: En cada ciclo de sondeo, el evaluador transfiere de forma autónoma los eventos que superan el umbral de 2 horas desde la sección activa hacia el histórico anterior.

  * **Refuerzo de Human-in-the-Loop (HITL) con Diálogos Draggables:**
    * `Views/ConfirmRemediationDialog.axaml`: Diálogo modal flotante sin decoraciones nativas que intercepta la orden de mitigación antes de enviarla al servidor. Muestra el comando en bloque monoespaciado (`iptables` o `kill -9`) y la argumentación del dictamen.
    * Soporte de Arrastre Libre (`BeginMoveDrag`): Implementación de captura de puntero en `ConfirmRemediationDialog` y `WarningDialog` para que las ventanas modales puedan moverse con naturalidad sobre el escritorio.

  * **Módulo de Estadísticas y Métricas Globales:**
    * `Models/ReportMetrics.cs`: Modelos de agregación (`MetricItem`) para la computación estadística en memoria.
    * `ViewModels/ReportsViewModel.cs`: Motor de procesamiento con LINQ sobre el histórico acumulado:
      * Desglose y ranking del **Top de IPs hostiles**.
      * Distribución por **vectores y tipologías de ataque**.
      * Detección de **áreas/subsistemas del servidor más atacados** (`AUTH`, `KERNEL`, `NGINX`, `SYS`, `FIM`).
      * Distribución porcentual por **nivel de severidad** (Crítica, Alta, Media, Baja, Informativa).
    * `Views/ReportsView.axaml`: Vista analítica modular con paneles de indicadores clave (KPIs), métricas consolidadas y barras de proporción reactivas.

  * **Navegación e Integración Multi-Vista:**
    * Alternancia sin Fricción (`MainWindow.axaml`): Integración en el menú lateral de accesos directos mediante `SplitView`. Al conmutar entre **Incidentes**  y **Estadísticas** , la vista activa se oculta o expone reactivamente mediante enlaces booleanos (`IsDashboardVisible` / `IsReportsVisible`), eliminando solapamientos visuales y conservando el estado de triaje intacto.

* **Pruebas y Resultados Obtenidos:**
  * **Persistencia comprobada:** Al reiniciar el cliente, la aplicación restaura instantáneamente decenas de alertas previas clasificándolas en la bandeja inferior de archivados.
  * **Validación HITL dual:** Se confirmaron con éxito autorizaciones de bloqueo perimetral (`iptables -I INPUT -s <IP> -j DROP`) ante ataques de fuerza bruta SSH / escaneos Nmap, y órdenes de terminación forzosa (`kill -9 <PID>`) ante procesos anómalos de shells reversas.
  * **Triaje y Cuadro de Mandos:** Transición fluida entre la pantalla de incidentes reactivos y el cuadro analítico de amenazas sin fugas de memoria ni renderizados duplicados.