# Test-Microsoft-Endpoints
Validates Microsoft 365, Microsoft Intune, and Microsoft admin portal network access.

---
# ES — Cómo interpretar los resultados del script

## Objetivo del script

Este script valida conectividad hacia:

* Microsoft 365
* Microsoft Intune
* Microsoft admin portals
* Dependencias comunes de enrollment, Autopilot, Win32 apps, IME, Remote Help, Delivery Optimization, etc.

El script NO valida funcionalidad completa del servicio.
Su propósito es validar:

* resolución DNS
* conectividad HTTPS/TLS
* reachability de endpoints
* posibles bloqueos de red/proxy/firewall/SSL inspection

---

# Qué valida el script

El script ejecuta varias pruebas por endpoint:

| Test      | Qué valida                       |
| --------- | -------------------------------- |
| DNS       | Resolución DNS                   |
| DirectTcp | Apertura TCP directa             |
| TLS       | Handshake TLS/SSL                |
| HttpProbe | Reachability HTTP/HTTPS          |
| UDP       | Validación UDP (ej. NTP UDP/123) |

---

# Cómo leer los resultados

## 1. DNS

### Resultado esperado

```text
DNS = Success
```

### Significado

El endpoint:

* resolvió correctamente
* el DNS es funcional
* no hay bloqueo DNS

### Si falla

```text
DNS = Failed
```

Puede indicar:

* bloqueo DNS
* proxy/firewall filtering
* problema de conectividad
* typo/FQDN inválido

### Importancia

MUY ALTA.

Si DNS falla:

* el endpoint normalmente NO será alcanzable.

---

# 2. DirectTcp

### Resultado esperado

```text
DirectTcp = Success
```

### Significado

El equipo pudo:

* abrir socket TCP directo
* alcanzar el puerto directamente

---

## IMPORTANTE

```text
DirectTcp = Failed
```

NO siempre significa problema.

En muchas redes enterprise:

* Zscaler
* Netskope
* Explicit Proxy
* PAC files
* SSL inspection
* transparent proxies

las conexiones TCP directas están bloqueadas “by design”.

En esos escenarios:

* DirectTcp puede fallar
* PERO el endpoint puede seguir siendo completamente funcional vía proxy HTTPS.

---

# 3. TLS

## Resultado esperado

```text
TLS = Success
```

### Significado

El endpoint:

* aceptó handshake TLS
* respondió en HTTPS
* el canal SSL/TLS funciona

---

# Interpretación

TLS es uno de los indicadores MÁS IMPORTANTES.

Si:

```text
TLS = Success
```

normalmente significa:

* el endpoint es alcanzable
* HTTPS funciona
* Intune/M365 deberían poder comunicarse

---

# Si TLS falla

Ejemplos:

* handshake terminated
* certificate validation failed
* unexpected EOF
* SSL/TLS negotiation failure

Puede indicar:

* SSL inspection
* proxy incompatibility
* TLS interception
* bloqueo HTTPS
* certificados corporativos

---

# IMPORTANTE — Intune y SSL Inspection

Microsoft indica que algunos endpoints Intune NO soportan SSL inspection, especialmente:

```text
*.manage.microsoft.com
*.dm.microsoft.com
```

Si TLS falla SOLO en esos endpoints:

* revisar SSL inspection
* excluir endpoints Intune del HTTPS decryption

---

# 4. HttpProbe

## Resultado esperado

```text
HttpProbe = Success
```

o incluso:

```text
HttpProbe = ReachableHttpError
```

---

# IMPORTANTE

Muchos endpoints Microsoft:

* NO responden HTTP 200
* responden 401/403/404

Eso sigue siendo GOOD.

Ejemplo:

```text
HttpProbe = ReachableHttpError
HTTP 403
```

Significa:

* el endpoint respondió
* HTTPS funciona
* el endpoint es reachable

NO significa bloqueo.

---

# Cómo determinar si un endpoint está funcional

## Endpoint funcional (OK)

Cualquiera de estos escenarios normalmente es GOOD:

### Escenario 1

```text
DNS         = Success
TLS         = Success
HttpProbe   = Success
```

### Escenario 2

```text
DNS         = Success
TLS         = Success
HttpProbe   = ReachableHttpError
```

### Escenario 3 (muy común en enterprise)

```text
DNS         = Success
DirectTcp   = Failed
TLS         = Success
HttpProbe   = Success
```

Esto normalmente significa:

* proxy corporativo
* diseño esperado
* endpoint funcional

---

# Endpoint posiblemente bloqueado

## Escenario problemático

```text
DNS         = Failed
```

o:

```text
TLS         = Failed
HttpProbe   = Failed
```

y además:

```text
DirectTcp   = Failed
```

Esto normalmente indica:

* bloqueo real
* proxy/firewall issue
* SSL inspection
* filtrado HTTPS

---

# Best Practices

## 1. Ejecutar desde el dispositivo afectado

Idealmente:

* device afectado
* misma red
* mismo proxy
* misma VPN
* mismo contexto del usuario

---

# 2. Ejecutar como Administrator

Recomendado para:

* pruebas de red
* sockets TCP
* validaciones TLS

---

# 3. No interpretar DirectTcp aislado

NO usar únicamente:

```text
DirectTcp = Failed
```

para concluir bloqueo.

Siempre revisar:

* TLS
* HttpProbe

---

# 4. Priorizar TLS y HttpProbe

Para Microsoft 365 e Intune modernos:

* HTTPS/TLS es lo más importante
* especialmente en ambientes con proxy

---

# 5. Revisar SSL Inspection

Si:

* TLS falla
* Intune enrollment falla
* IME falla
* Win32 apps fallan
* Autopilot falla

validar:

* SSL decryption
* HTTPS inspection
* proxy certificates

---

# 6. Validar wildcards en firewall

El script NO puede probar directamente:

```text
*.manage.microsoft.com
```

porque wildcards no son FQDN reales.

Pero sí exporta:

* allowlist references
* wildcard references
* CIDR ranges

para uso del equipo de networking.

---

# EN — How to interpret the script results

# Script purpose

This script validates connectivity to:

* Microsoft 365
* Microsoft Intune
* Microsoft admin portals
* Common enrollment, Autopilot, IME, Win32 app, Remote Help, and Delivery Optimization dependencies

The script does NOT validate full service functionality.

Its purpose is to validate:

* DNS resolution
* HTTPS/TLS connectivity
* endpoint reachability
* possible proxy/firewall/SSL inspection issues

---

# What the script validates

| Test      | Purpose                                 |
| --------- | --------------------------------------- |
| DNS       | DNS resolution                          |
| DirectTcp | Direct TCP socket connectivity          |
| TLS       | TLS/SSL handshake                       |
| HttpProbe | HTTP/HTTPS reachability                 |
| UDP       | UDP connectivity (example: NTP UDP/123) |

---

# How to read the results

# 1. DNS

## Expected result

```text
DNS = Success
```

## Meaning

The endpoint:

* resolved correctly
* DNS is functional
* no DNS filtering/blocking detected

---

## If DNS fails

```text
DNS = Failed
```

This may indicate:

* DNS filtering
* firewall/proxy filtering
* connectivity issue
* invalid FQDN

---

# 2. DirectTcp

## Expected result

```text
DirectTcp = Success
```

## Meaning

The device was able to:

* open a direct TCP socket
* reach the destination port directly

---

# IMPORTANT

```text
DirectTcp = Failed
```

does NOT always indicate a problem.

In many enterprise environments:

* Zscaler
* Netskope
* Explicit proxies
* PAC files
* SSL inspection
* transparent proxies

direct outbound TCP connections are intentionally blocked.

In those environments:

* DirectTcp may fail
* BUT the endpoint may still be fully reachable through HTTPS proxy communication.

---

# 3. TLS

## Expected result

```text
TLS = Success
```

## Meaning

The endpoint:

* accepted TLS handshake
* responded over HTTPS
* SSL/TLS communication is functional

---

# Interpretation

TLS is one of the MOST IMPORTANT indicators.

If:

```text
TLS = Success
```

this usually means:

* the endpoint is reachable
* HTTPS works correctly
* Intune/M365 communication should function

---

# If TLS fails

Examples:

* handshake terminated
* certificate validation failed
* unexpected EOF
* SSL/TLS negotiation failure

This may indicate:

* SSL inspection
* proxy incompatibility
* TLS interception
* HTTPS filtering
* corporate certificates

---

# IMPORTANT — Intune and SSL Inspection

Microsoft states that some Intune endpoints do NOT support SSL inspection, especially:

```text
*.manage.microsoft.com
*.dm.microsoft.com
```

If TLS fails ONLY for those endpoints:

* review SSL inspection policies
* exclude Intune endpoints from HTTPS decryption

---

# 4. HttpProbe

## Expected result

```text
HttpProbe = Success
```

or even:

```text
HttpProbe = ReachableHttpError
```

---

# IMPORTANT

Many Microsoft endpoints:

* do NOT return HTTP 200
* return 401/403/404 instead

This is still GOOD.

Example:

```text
HttpProbe = ReachableHttpError
HTTP 403
```

This means:

* the endpoint responded
* HTTPS connectivity works
* the endpoint is reachable

This does NOT indicate blocking.

---

# How to determine whether an endpoint is functional

# Functional endpoint (OK)

Any of these scenarios is usually GOOD:

## Scenario 1

```text
DNS         = Success
TLS         = Success
HttpProbe   = Success
```

## Scenario 2

```text
DNS         = Success
TLS         = Success
HttpProbe   = ReachableHttpError
```

## Scenario 3 (very common in enterprise environments)

```text
DNS         = Success
DirectTcp   = Failed
TLS         = Success
HttpProbe   = Success
```

This usually indicates:

* corporate proxy
* expected network design
* endpoint is functional

---

# Possibly blocked endpoint

## Problematic scenario

```text
DNS         = Failed
```

or:

```text
TLS         = Failed
HttpProbe   = Failed
```

and additionally:

```text
DirectTcp   = Failed
```

This usually indicates:

* actual blocking
* proxy/firewall issue
* SSL inspection issue
* HTTPS filtering

---

# Best Practices

# 1. Run from the affected device

Ideally:

* affected device
* same network
* same proxy
* same VPN
* same user context

---

# 2. Run as Administrator

Recommended for:

* network testing
* TCP sockets
* TLS validation

---

# 3. Do NOT interpret DirectTcp alone

Do NOT use only:

```text
DirectTcp = Failed
```

to conclude that the endpoint is blocked.

Always review:

* TLS
* HttpProbe

---

# 4. Prioritize TLS and HttpProbe

For modern Microsoft 365 and Intune environments:

* HTTPS/TLS is the most important validation
* especially in proxy-based enterprise networks

---

# 5. Review SSL Inspection

If:

* TLS fails
* Intune enrollment fails
* IME fails
* Win32 apps fail
* Autopilot fails

review:

* SSL decryption
* HTTPS inspection
* proxy certificates

---

# 6. Validate firewall wildcards

The script cannot directly test:

```text
*.manage.microsoft.com
```

because wildcards are not real FQDNs.

However, the script exports:

* allowlist references
* wildcard references
* CIDR ranges

for networking/firewall teams.
