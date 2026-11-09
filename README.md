# SentinelAI SOC L2 — Plataforma de Análisis Forense de Incidentes

[![Framework](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-orange?style=for-the-badge)](https://attack.mitre.org/)
[![Forensics](https://img.shields.io/badge/Integridad-SHA--256%20Verificada-emerald?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
[![Architecture](https://img.shields.io/badge/Auditor%C3%ADa-SOC%20Nivel%202-007acc?style=for-the-badge)](#)
[![UX Laws](https://img.shields.io/badge/UX%20Laws-26%2F26%20Implementadas-purple?style=for-the-badge)](https://lawsofux.com/)
[![License](https://img.shields.io/badge/Licencia-MIT-green?style=for-the-badge)](LICENSE)

**SentinelAI SOC L2** es una plataforma web analítica de grado forense diseñada para investigar exportaciones de registros SIEM (formatos `.xlsx` y `.csv`). Proporciona trazabilidad criptográfica inmutable mediante **SHA-256**, un motor de **detección de anomalías estadísticas multivariables** en tiempo real, matriz interactiva con cobertura **MITRE ATT&CK**, y exportación de **informes consolidados (Ejecutivo + Técnico) en PDF** y **evidencias forenses estructuradas en JSON**.

La plataforma procesa el 100% de los datos en la memoria del navegador del analista, garantizando confidencialidad absoluta sin requerir servidores externos, tokens de API de pago ni alterar los sistemas en producción.

---

## 🌟 Capacidades Funcionales Reales

- **Integridad Forense Criptográfica (SHA-256):** Validación en tiempo real mediante la Web Crypto API del archivo original (`0e5d5de5...`) y referencia exacta de fila de origen (`S1-Rxx`) para cada evento auditado.
- **Motor de Detección de Anomalías Estadísticas Multivariable:**
  - *Information Surprisal:* $-\log_2(p)$ sobre la frecuencia de ocurrencia de cada pareja Proveedor/Evento.
  - *Z-Score de Línea de Comandos:* Detección matemática de longitudes atípicas y patrones de ejecución ofuscada (`EncodedCommand`, `vssadmin`, `7z`, `tar`, scripts web).
  - *Riesgo de Exposición de Red:* Identificación inmediata de tráfico que involucra direcciones IP públicas o destinos no corporativos.
- **Explorador Forense de Eventos:** Barra de filtrado sintáctico, selectores dinámicos por Host, Usuario y Severidad, y visualizador detallado de evento (vista tabular y objeto JSON estructurado).
- **Matriz Interactiva MITRE ATT&CK:** Clasificación táctica y técnica de los 123 eventos sospechosos identificados en el dataset.
- **Auditoría de 26 Leyes de UX:** Diseño cognitivo orientado a analistas de seguridad para reducir fatiga mental y tiempo de respuesta en incidentes (Leyes de Doherty, Fitts, Hick, Miller, Von Restorff, Zeigarnik, etc.).
- **Doble Entregable Forense:**
  1. *PDF Consolidado Único:* Resumen Ejecutivo para la Dirección + Anexo Técnico Detallado con observables y mitigaciones.
  2. *JSON Forense Estructurado:* Cadena de custodia, metadatos, catálogo de incidentes y evidencias normalizadas.

---

## 🗂️ Estructura del Repositorio

```text
├── index.html                    # Aplicación web completa (SPA en HTML5, Tailwind CSS y JavaScript)
├── README.md                     # Documentación técnica, ejecutiva y forense del proyecto
├── LICENSE                       # Licencia de código abierto MIT
├── .gitignore                    # Exclusiones de control de versiones
├── data/
│   └── SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx   # Dataset oficial del reto (715 eventos)
└── .github/
    └── workflows/
        └── pages.yml             # Despliegue automatizado continuo a GitHub Pages
```

---

## 🔍 Catálogo de Incidentes Auditados (Dataset Oficial - 715 Eventos)

| ID | Incidente | Severidad | MITRE ATT&CK | Observables Clave (IOCs) |
| :--- | :--- | :---: | :--- | :--- |
| **INC-01** | Password Spraying Externo y Compromiso de Dominio | **Alto** | T1110.003, T1078.002 | `203.0.113.74`, `CORP\mgarcia`, DC-01, WS-031 |
| **INC-02** | Intrusión RDP, Movimiento Lateral & Exfiltración | **Alto** | T1021.001, T1059.001, T1041 | `CORP\admin`, `tar.exe`, `Budget2027.xlsx`, `203.0.113.88:443` |
| **INC-03** | Pre-Ransomware: Borrado de VSS y Harvesting Financiero | **Alto** | T1490, T1059.001, T1039 | `CORP\backupsvc`, `vssadmin delete shadows`, `FY2026\document_*.xlsx` |
| **INC-04** | Empaquetado y Exfiltración Masiva de Archivo Legal | **Alto** | T1560.001, T1048 | `CORP\rrojas`, `7z.exe C:\Legal\*.docx`, 241.57 MB vía HTTPS POST |
| **INC-05** | Persistencia mediante Tarea Programada y Servicio Malicioso | **Alto** | T1053.005, T1543.003 | `CORP\helpdesk`, `wuhelper.exe`, `\Microsoft\Windows\UpdateCheck` |
| **INC-06** | Ataque Web a IIS y Ejecución Remota de Webshell | **Alto** | T1190, T1505.003, T1059.003 | `192.0.2.91`, `/uploads/test.aspx?cmd=whoami`, `DefaultAppPool` |

---

## 🧠 Arquitectura Analítica: Detección Multivariable

El motor analítico evalúa cada registro del dataset calculando una puntuación normalizada de anomalía ($0.00 \le \text{Score} \le 1.00$):

$$\text{AnomalyScore} = 0.35 \times R_{\text{net}} + 0.30 \times A_{\text{cmd}} + 0.20 \times S_{\text{rarity}} + 0.15 \times W_{\text{sev}}$$

Donde:
1. **$R_{\text{net}}$ (Riesgo de Red):** Pondera eventos con origen o destino en direcciones IP externas públicas.
2. **$A_{\text{cmd}}$ (Anomalía de Comando):** Z-score de longitud de comando sumado a tokens heurísticos críticos (`EncodedCommand`, `vssadmin`, `delete shadows`, `7z`, `tar`, `whoami`).
3. **$S_{\text{rarity}}$ (Surprisal):** Contenido de información $-\log_2(p)$ sobre la frecuencia del par `Log_Source::Event_ID`.
4. **$W_{\text{sev}}$ (Ponderación SIEM):** Severidad original declarada en el registro de origen.

---

## 🚀 Puesta en Marcha

### Opción 1: Abrir Directamente en el Navegador
1. Clona este repositorio:
   ```bash
   git clone https://github.com/<tu-usuario>/sentinelai-soc-l2.git
   ```
2. Abre `index.html` en cualquier navegador web moderno (Edge, Chrome, Firefox).
3. La aplicación procesará y presentará de inmediato el dataset oficial y sus métricas.

### Opción 2: Servidor Local
```powershell
# Usando Python:
python -m http.server 8080

# Usando Node.js:
npx serve .
```
Abre en tu navegador `http://localhost:8080`.

---

## 📄 Cumplimiento de Estándares Forenses

- **NIST SP 800-61 Rev. 2:** Guía de Manejo de Incidentes de Seguridad de la Información (Fases de Detección, Análisis y Contención).
- **MITRE ATT&CK v14:** Cobertura táctica y técnica explícita en todos los hallazgos.
- **Cadena de Custodia Criptográfica:** Hash SHA-256 inmutable de la fuente de evidencia.

---

## 👤 Autor y Licencia

Desarrollado como proyecto de análisis forense SOC L2. Distribuido bajo licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
