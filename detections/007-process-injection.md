# Incidente 007: Sysmon Event 8: CreateRemoteThread

## Resumen
- **Fecha/hora:** 2026-09-16 19:16 (UTC+2)
- **Regla(s) que saltó:** Custom rule: Sysmon Event 8: CreateRemoteThread from C:\\AtomicRedTeam\\atomics\\T1055\\bin\\x64\\CreateRemoteThread.exe to C:\\Windows\\System32\\WerFault.exe (100109)
- **Técnica MITRE ATT&CK:** T1055 - Process Injection
- **Endpoint afectado:** WIN10-LAB
- **Severidad:** Alta
- **Veredicto:** Verdadero positivo

## 1. Ejecución del ataque
Se añadió una regla personalizada a Wazuh para detectar los sysmon event 8 del endpoint de Windows 10, para así poder detectar `CreateRemoteThread`:
```xml
<group name="windows,sysmon,">
  <rule id="100109" level="10">
    <if_group>sysmon_event8</if_group>
    <description>Sysmon Event 8: CreateRemoteThread from $(win.eventdata.sourceImage) to $(win.eventdata.targetImage)</description>
    <mitre>
      <id>T1055</id>
    </mitre>
  </rule>
</group>
```

Y posteriormente se realizó un ataque de _Process Injection_ utilizando _CreateRemoteThread_ WinAPI
```powershell
Invoke-AtomicTest T1055 -TestNumbers 9
```


## 2. Evidencia recolectada
- Captura del evento en Wazuh
![wazuh](../images/007-process-injection-wazuh.png)
- Usuario/Proceso: vboxuser → CreateRemoteThread.exe
- Línea de comando completa: `"powershell.exe" & {$process = Start-Process C:\Windows\System32\werfault.exe -passthru
C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThread.exe -pid $process.Id -debug}`
- Eventos correlacionados: Ejecución de `C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThread.exe` desde powershell `rule.id:92027` y `data.win.system.eventID:1` y posterior inyección de proceso.

## 3. Investigación (paso a paso)
1. Detecté primero la ejecución de un binario como administrador (`IntegrityLevel: High`) desde el usuario `vboxuser` desde powershell `C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThread.exe` con objetivo `C:\Windows\System32\werfault.exe` (`rule.id:92027` y `data.win.system.eventID:1`)
```
"Process Create:
RuleName: technique_id=T1059.001,technique_name=PowerShell
UtcTime: 2026-09-16 17:16:10.896
ProcessGuid: {e65a69a6-ceda-6aaa-4901-000000000b00}
ProcessId: 1072
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.19041.546 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: "powershell.exe" & {$process = Start-Process C:\Windows\System32\werfault.exe -passthru
C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThread.exe -pid $process.Id -debug}
CurrentDirectory: C:\Users\vboxuser\AppData\Local\Temp\
User: WIN10-LAB\vboxuser
LogonGuid: {e65a69a6-ca4a-6aaa-ca93-030000000000}
LogonId: 0x393CA
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=F43D9BB316E30AE1A3494AC5B0624F6BEA1BF054,MD5=04029E121A0CFA5991749937DD22A1D9,SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F,IMPHASH=7C955A0ABC747F57CCC4324480737EF7
ParentProcessGuid: {e65a69a6-cb53-6aaa-0501-000000000b00}
ParentProcessId: 7036
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
ParentUser: WIN10-LAB\vboxuser"
```
2. Posteriormente detecté un sysmon event 8 detectando la creación de un CreateRemoteThread indicando una posible inyección de proceso hacia `C:\Windows\System32\WerFault.exe`
```
"CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-09-16 17:16:11.820
SourceProcessGuid: {e65a69a6-cedb-6aaa-4c01-000000000b00}
SourceProcessId: 4920
SourceImage: C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThread.exe
TargetProcessGuid: {e65a69a6-cedb-6aaa-4b01-000000000b00}
TargetProcessId: 5368
TargetImage: C:\Windows\System32\WerFault.exe
NewThreadId: 2076
StartAddress: 0x000001F184540000
StartModule: -
StartFunction: -
SourceUser: WIN10-LAB\vboxuser
TargetUser: WIN10-LAB\vboxuser"
```
3. No se observaron accesos en remoto `data.win.system.eventID:3` ni nuevos archivos creados `data.win.system.eventID:11`
4. No se produjo ningún acceso a un proceso `data.win.system.eventID:10`
5. Tampoco se observó una escalada de privilegios `data.win.system.eventID:4732` ni persistencia `data.win.system.eventID:4698`
6. No se ha identificado software autorizado que explique esta actividad.

## 4. Análisis
Posiblemente implique un _process injection_ hacia `WerFault.exe` puesto que se ha ejecutado desde powershell con permisos de administrador y CreateRemoteThread proviene de una ruta relacionada con tests de Atomic, escalo a N2 para pedir ayuda y seguir investigando.

## 5. Acciones de respuesta
- Escalada a N2
- Aislar host de red
- Solicito análisis forense de la memoria

## 6. Recomendaciones de mejora (detection engineering)
- Crear una alerta específica para sysmon event 8 puesto que wazuh de normal no genera una alerta visible, especialmente una alerta que priorice procesos origen desconocidos y destinos sensibles.
- Crear una _allowlist_ precisa para identificar las herramientas legítimas que pueden utilizar esta función.


## 7. Lecciones aprendidas
He aprendido lo que es CreateRemoteThread y para lo que se utiliza, también he aprendido a crear nuevas reglas para Wazuh.
