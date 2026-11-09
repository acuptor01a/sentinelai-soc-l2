# SentinelAI SOC L2 — Plataforma de Análisis Forense de Incidentes e Inteligencia Artificial

[![Live Demo](https://img.shields.io/badge/Demo-GitHub%20Pages-blue?style=for-the-badge&logo=github)](https://luisfer6.github.io/)
[![Framework](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-orange?style=for-the-badge)](https://attack.mitre.org/)
[![Forensics](https://img.shields.io/badge/Integridad-SHA--256%20Verificada-emerald?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
[![Design](https://img.shields.io/badge/Inspirado%20en-Wazuh%20SIEM%20%26%20XDR-007acc?style=for-the-badge)](https://wazuh.com/)
[![UX Laws](https://img.shields.io/badge/UX%20Laws-26%2F26%20Implementadas-purple?style=for-the-badge)](https://lawsofux.com/)
[![License](https://img.shields.io/badge/Licencia-MIT-green?style=for-the-badge)](LICENSE)

**SentinelAI SOC L2** es una plataforma web analítica de grado forense diseñada para investigar exportaciones de registros SIEM (Excel `.xlsx` y `.csv`). Cuenta con una interfaz dark-mode avanzada inspirada en **Wazuh SIEM / Kibana**, trazabilidad criptográfica **SHA-256**, motor de **detección de anomalías estadísticas multivariables** en tiempo real, matriz interactiva **MITRE ATT&CK**, y exportación de **informes consolidados (Ejecutivo + Técnico) en PDF** y **evidencias forenses estructuradas en JSON**.

La plataforma procesa el 100% de los datos en la memoria del navegador del analista, garantizando confidencialidad absoluta sin requerir servidores intermediarios, tokens de API de pago ni instalaciones pesadas.

---

## 🌟 Características Principales

- **Integridad Forense Criptográfica (SHA-256):** Validación en tiempo real con Web Crypto API del archivo original (`0e5d5de5...`) y trazabilidad de celda física (`S1-Rxx`) para cada evento.
- **Motor de Anomalías Estadísticas Multivariable:**
  - *Information Surprisal:* $-\log_2(p)$ sobre parejas Proveedor/Evento.
  - *Z-Score de Línea de Comandos:* Detección de payloads ofuscados (Base64, `vssadmin`, `7z`, `tar`, webshells).
  - *Riesgo de Red Externo:* Ponderación inmediata para orígenes o destinos no corporativos.
- **Visualización y Búsqueda Estilo Wazuh XDR:** Barra de búsqueda DQL, selectores/facets dinámicos de Host, Usuario y Severidad, y visualizador inspector de documentos (Vista Tabla y JSON nativo de alerta SIEM).
- **Matriz Interactiva MITRE ATT&CK:** Mapeo táctico completo desde Reconocimiento hasta Exfiltración e Impacto.
- **Auditoría de 26 Leyes de UX:** Diseño cognitivo optimizado para analistas de SOC bajo estrés (Leyes de Doherty, Fitts, Hick, Miller, Von Restorff, Zeigarnik, etc.).
- **Doble Entregable Forense:**
  1. *PDF Consolidado Único:* Resumen Ejecutivo para la Alta Dirección + Anexo Técnico Detallado.
  2. *JSON Forense Estructurado:* Cadena de custodia, metadatos, catálogo de incidentes y evidencias normalizadas.

---

## 🗂️ Estructura del Repositorio

```text
├── index.html                    # Aplicación web completa (SPA con Tailwind CSS, Chart.js, SheetJS y html2pdf)
├── README.md                     # Documentación técnica, ejecutiva y forense del proyecto
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

El motor analítico no se limita a cadenas de texto estáticas; calcula una puntuación normalizada de anomalía ($0.00 \le \text{Score} \le 1.00$) para cada evento:

$$\text{AnomalyScore} = 0.35 \times R_{\text{net}} + 0.30 \times A_{\text{cmd}} + 0.20 \times S_{\text{rarity}} + 0.15 \times W_{\text{sev}}$$

Donde:
1. **$R_{\text{net}}$ (Riesgo de Red):** Evalúa exposición pública frente a subredes privadas RFC 1918.
2. **$A_{\text{cmd}}$ (Anomalía de Comando):** Z-score de longitud de comando sumado a tokens heurísticos críticos (`EncodedCommand`, `vssadmin`, `delete shadows`, `7z`, `tar`, `whoami`).
3. **$S_{\text{rarity}}$ (Surprisal):** Contenido de información $-\log_2(p)$ sobre la frecuencia de aparición del par `Log_Source::Event_ID`.
4. **$W_{\text{sev}}$ (Ponderación SIEM):** Severidad original declarada en el registro de origen.

---

## 🚀 Puesta en Marcha

### Opción 1: Abrir Directamente en el Navegador
1. Clona o descarga este repositorio:
   ```bash
   git clone https://github.com/<tu-usuario>/sentinelai-soc-l2.git
   ```
2. Haz doble clic sobre `index.html` en el explorador de archivos.
3. La aplicación cargará automáticamente los 715 registros del reto con sus métricas y gráficos.

### Opción 2: Ejecutar con Servidor Local Ligero
Si deseas servirlo mediante HTTP local:
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

Desarrollado como proyecto final de certificación SOC L2. Distribuido bajo licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
