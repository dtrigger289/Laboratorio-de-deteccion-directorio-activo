# 📋 Playbook SOC: PB-01 - Detección de Kerberoasting (T1558.003)

- **Severidad:** Alta (Nivel 12 en Wazuh)
- **Regla Asociada:** `100100` (`local_rules.xml`) / `win_security_kerberoasting_rc4.yml`
- **MITRE ATT&CK:** Credential Access - Steal or Forge Kerberos Tickets: Kerberoasting (`T1558.003`)
- **Fuente de Telemetría:** Windows Security Auditing (`Event ID 4769`)

---

## 1. Triaje y Análisis (Nivel 1 / Nivel 2)
Cuando salte la alerta `100100`, el analista debe extraer los siguientes campos del evento en Wazuh Discover:
1. **Cuenta Objetivo (`data.win.eventdata.serviceName`):** Identificar qué cuenta de servicio tiene registrado el SPN atacado (ej. `svc_sql`).
2. **Origen de la Petición (`data.win.eventdata.ipAddress`):** Identificar desde qué máquina interna o VPN se solicitó el ticket TGS.
3. **Usuario Solicitante (`data.win.eventdata.targetUserName`):** Identificar qué cuenta de dominio inicial fue comprometida para realizar la petición.
4. **Validación de Falso Positivo:** Confirmar que `ticketEncryptionType` es `0x17` (RC4-HMAC) y `ticketOptions` es `0x40810000`. Verificar si el host origen corresponde a un servidor de aplicaciones legítimo que aún no soporta AES256.

## 2. Búsqueda de Amenazas Relacionadas (Threat Hunting)
Comprobar en Wazuh si el atacante ya ha crackeado la contraseña de la cuenta de servicio y la está utilizando para iniciar sesión o moverse lateralmente:

`data.win.eventdata.targetUserName: "svc_sql" AND (data.win.system.eventID: "4624" OR rule.id: (100501 OR 100502 OR 100503 OR 100504))`

## 3. Contención y Erradicación
1. **Rotación inmediata de credenciales:** Cambiar la contraseña de la cuenta de servicio afectada (`svc_sql`) por una de más de 25 caracteres generada aleatoriamente.
2. **Revocación de sesiones:** Purgar los tickets Kerberos activos (`klist purge`) e invalidar sesiones de la cuenta solicitante inicial comprometida.
3. **Aislamiento del Host Origen:** Si la IP origen (`ipAddress`) pertenece a una estación de trabajo comprometida o un host no autorizado en la subred `192.168.56.0/24`, aislar el endpoint en red.

## 4. Hardening y Lecciones Aprendidas (Post-Incidente)
- **Deshabilitar RC4 en cuentas de servicio:** Forzar el uso exclusivo de cifrado **AES128/AES256** marcando las casillas correspondientes en las propiedades de la cuenta dentro de Active Directory (`msDS-SupportedEncryptionTypes`).
- **Migración a gMSA:** Sustituir las cuentas de servicio tradicionales con SPN por *Group Managed Service Accounts* (gMSA), cuyas contraseñas de 120 caracteres rotan automáticamente.
- **Mínimo Privilegio:** Auditar que ninguna cuenta con SPN pertenezca al grupo `Domain Admins`.
