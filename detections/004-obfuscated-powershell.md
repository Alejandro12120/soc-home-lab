# Incidente 004: Suspicious Windows cmd shell execution

## Resumen
- **Fecha/hora:** 2026-09-13 17:47 (UTC+2)
- **Regla(s) que saltó:** Suspicious Windows cmd shell execution (92032)
- **Técnica MITRE ATT&CK:** T1059.003 - Windows Command Shell
- **Endpoint afectado:** WIN10-LAB
- **Severidad:** Alta
- **Veredicto:** Verdadero positivo

## 1. Ejecución del ataque
Se ejecutó un test de Atomic Red Team (PowerShell Command Execution)
```powershell
Invoke-AtomicTest T1059.001 -TestNumber 17
```


## 2. Evidencia recolectada
- Captura del evento en Wazuh
![Wazuh](../images/004-obfuscated-powershell-wazuh.png)
- Usuario/Proceso: vboxuser → powershell.exe
- Línea de comando completa: 
```
"Process Create:
RuleName: technique_id=T1059.001,technique_name=PowerShell
UtcTime: 2026-09-13 15:47:51.504
ProcessGuid: {e65a69a6-c5a7-6aa6-ce01-000000000700}
ProcessId: 5900
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.19041.546 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe  -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
CurrentDirectory: C:\Users\vboxuser\AppData\Local\Temp\
User: WIN10-LAB\vboxuser
LogonGuid: {e65a69a6-bf35-6aa6-3246-040000000000}
LogonId: 0x44632
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=F43D9BB316E30AE1A3494AC5B0624F6BEA1BF054,MD5=04029E121A0CFA5991749937DD22A1D9,SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F,IMPHASH=7C955A0ABC747F57CCC4324480737EF7
ParentProcessGuid: {e65a69a6-c5a7-6aa6-cc01-000000000700}
ParentProcessId: 5172
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "cmd.exe" /c powershell.exe -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
ParentUser: WIN10-LAB\vboxuser"
```

## 3. Investigación (paso a paso)
1. Detección de un script de PowerShell obfuscado en base64 ejecutado desde carpeta Temp
2. Cadena de procesos cmd -> powershell y con privilegios elevados
3. Se observa que durante la ejecución del script, el mismo proceso (Guid: `{e65a69a6-c5a7-6aa6-ce01-000000000700}`) creó el archivo temporal _PSScriptPolicyTest.ps1, artefacto benigno de la comprobación interna de políticas de PowerShell (AppLocker/WDAC). Se correlacionó por ProcessGuid descartando un segundo vector de ataque.
4. No se ha podido observar ningún comportamiento anómalo extra.
5. Se ha podido desobfuscar manualmente el script.

## 4. Análisis
Debido a la multitud de indicadores sospechosos (script en base64, carpeta temporal y privilegios elevados) clasifico esta alerta con una severidad alta debido al riesgo inminente que supone.

## 5. Acciones de respuesta
- Escalada a N2
- Aislado de máquina
- Realizar análisis forense al script 

## 6. Recomendaciones de mejora (detection engineering)
Se recomienda deshabilitar los permisos de administrador a las cuentas no esenciales. Aplicando el principio _Least privilege_

## 7. Lecciones aprendidas
He aprendido lo importante que es el principio _Least privilege_ puesto que un atacante podría fácilmente ejecutar un script con permisos de administrador sin que el usuario sea consciente de ello.

## 8. Referencias
- MITRE ATT&CK: https://attack.mitre.org/techniques/TXXXX/
- [Documentación/artículos consultados]
