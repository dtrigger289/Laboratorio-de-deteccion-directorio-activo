```mermaid
flowchart TB
    subgraph Host["💻 Linux Host (16 GB RAM - VirtualBox)"]
        subgraph NAT["🌐 Red NAT: laboratoriodeteccion (192.168.56.0/24)"]
            
            KALI["🐉 KALI (Red Team)\n192.168.56.x\nImpacket | Kerberoast | Spraying"]
            
            subgraph AD["🏢 Dominio: deviltrigger.local"]
                DC01["🗄️ DC01 (Windows Server 2022)\n192.168.56.10\nAD DS | KDC | SPN: svc_sql\nSysmon + Wazuh Agent 4.9.2"]
                CLIENT01["🖥️ CLIENT01 (Windows 11 Ent.)\n192.168.56.20\nWorkstation Corporativa\nSysmon + Wazuh Agent 4.9.2"]
            end
            
            WAZUH["🛡️ WAZUH-SRV (Ubuntu 24.04 LTS)\n192.168.56.8\nWazuh 4.9 All-in-One\nCustom Rules + MITRE ATT&CK"]
        end
    end

    KALI -- "1. Ataques AD / Lateral Movement\n(T1110.003, T1558.003, T1021.002, T1047)" --> DC01
    KALI -. "2. Post-Explotación / LOLBins\n(T1003.001, T1218)" .-> CLIENT01
    DC01 == "3. Telemetría (TCP 1514/1515)\nEvent 4625, 4688, 4769, 7045 + Sysmon" ==> WAZUH
    CLIENT01 == "3. Telemetría (TCP 1514/1515)\nSysmon ID 1, 10, 11 + Security" ==> WAZUH
```

## 🚨 Playbooks de Respuesta a Incidentes (SOP) y Hardening

Cada detección desarrollada en el laboratorio cuenta con su procedimiento operativo estándar (SOP) para analistas SOC N1/N2, detallando las fases de **Triaje, Threat Hunting, Contención y Hardening de Active Directory**:

- 📄 **[PB-01: Respuesta ante Kerberoasting y Compromiso de Cuentas de Servicio (T1558.003)](./playbooks/PB-01-Kerberoasting.md)**
- 📄 **[PB-02: Respuesta ante Movimiento Lateral Remoto vía PsExec y WMI (T1021.002 / T1047)](./playbooks/PB-02-Movimiento-Lateral.md)**
