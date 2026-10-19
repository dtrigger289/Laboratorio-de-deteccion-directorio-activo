# 📋 Playbook SOC: PB-02 - Movimiento Lateral Remoto (T1021.002 / T1047)

- **Severidad:** Crítica (Nivel 12–15 en Wazuh)
- **Reglas Asociadas:** `100501`, `100502` (PsExec) | `100503`, `100504` (WMIExec)
- **MITRE ATT&CK:** Lateral Movement (`T1021.002`), Execution (`T1047`, `T1569.002`), Persistence (`T1543.003`)
- **Fuente de Telemetría:** Windows System (`Event ID 7045`), Sysmon (`Event ID 1`, `Event ID 11`)

---

## 1. Triaje y Análisis Forense Rápido
Un impacto en las reglas `100501–100504` contra un servidor crítico como `DC01` (`192.168.56.10`) indica que el adversario ya posee credenciales con privilegios administrativos.

### Caso A: Alerta por Impacket PsExec (`100501` / `100502`)
1. Revisar `data.win.eventdata.serviceName` (ej. servicio aleatorio de 4 letras como `gmnF`) y `data.win.eventdata.imagePath` (ej. `%systemroot%\sKWQIKPF.exe`).
2. **Diferenciar Ejecución Exitosa vs. Bloqueo Antivirus:**
   - Buscar eventos posteriores de `Sysmon Event ID 1` donde `parentImage` sea el binario aleatorio depositado en `C:\Windows\`.
   - Si no existen procesos hijos y aparece un evento de Windows Defender (`Event ID 1116/1117`), el payload fue bloqueado antes de arrancar el servicio, pero **las credenciales administrativas utilizadas siguen comprometidas**.

### Caso B: Alerta por Impacket WMIExec (`100503` / `100504`)
1. Inspeccionar el campo `data.win.eventdata.commandLine` para identificar qué comandos ejecutó el atacante (ej. reconocimiento con `whoami` o evasión defensiva con `Set-MpPreference`).
2. Correlacionar con eventos `Event ID 4624` (`LogonType: 3` - Red) en el mismo segundo para identificar la **IP de origen del atacante** y si utilizó **Pass-the-Hash** (`AuthenticationPackageName: NTLM`).

## 2. Contención y Erradicación
1. **Aislamiento de Red:** Bloquear inmediatamente el tráfico SMB (445/TCP) y RPC/WMI (135/TCP y puertos dinámicos) desde la IP atacante identificada en el `Event ID 4624`.
2. **Revocación de Cuentas Privilegiadas:** Deshabilitar o rotar la contraseña de la cuenta administrativa utilizada. Al tratarse de un Controlador de Dominio (`DC01`), programar el doble reseteo de la cuenta `krbtgt` ante posible persistencia vía *Golden Ticket* o extracción de `NTDS.dit`.
3. **Limpieza de Artefactos en el Endpoint:**
   - Eliminar cualquier servicio malicioso remanente (`sc delete <ServiceName>`) y borrar el ejecutable en `C:\Windows\`.
   - Verificar que la protección en tiempo real de Windows Defender (`DisableRealtimeMonitoring $false`) y los perfiles del Firewall (`netsh advfirewall set allprofiles state on`) estén activos.

## 3. Hardening y Lecciones Aprendidas (Post-Incidente)
- **Restricción de Tráfico Administrativo:** Bloquear por GPO en el Firewall de Windows la entrada de SMB (445) y WMI/RPC (135) entre estaciones de trabajo (Workstation-to-Workstation) y permitir el acceso a `DC01` únicamente desde una máquina de salto administrativa (PAW / Jump Host).
- **Grupo Protected Users:** Incluir a las cuentas administrativas dentro del grupo de seguridad `Protected Users` de Active Directory para impedir el uso de autenticación NTLM (*Pass-the-Hash*) y forzar Kerberos con cifrado AES.
- **Protección contra Tampering:** Habilitar *Tamper Protection* en Microsoft Defender para impedir que un atacante con privilegios locales desactive el monitoreo en tiempo real mediante comandos de PowerShell.
