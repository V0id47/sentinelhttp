# SentinelHTTP

[English](README.md) · [Español](README.es.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md)

SentinelHTTP es una herramienta local y acotada para evaluar la configuración
HTTP/HTTPS. Captura una respuesta por defecto, explica hallazgos conservadores
con su evidencia, calcula una **Puntuación de configuración** que muestra su
cobertura, compara informes compatibles y los presenta en un panel local. Es
un proyecto profesional de portfolio de ciberseguridad; no demuestra
explotabilidad ni la seguridad de un sitio completo.

Usala solo en sistemas propios o para los que tengas autorización de evaluación.

## Inicio rápido

Necesitás Go 1.26 o posterior (CI usa 1.27.1). Los assets del panel incluidos
en el repositorio funcionan sin Node.js; para reconstruirlos se requieren
Node.js 24 y npm. Consultá la [instalación](docs/install.md).

```console
go run ./cmd/sentinelhttp version
go run ./cmd/sentinelhttp scan http://127.0.0.1:8080/ --allow-private --format json --output report.json --lang es
go run ./cmd/sentinelhttp serve report.json
```

El ejemplo supone un servicio HTTP local en el puerto 8080. El panel escucha
en un puerto aleatorio de `127.0.0.1`; `--no-open` evita abrir el navegador.
SentinelHTTP nunca sobrescribe un archivo de salida existente.

Para HTTPS en Windows, macOS e iOS debés indicar un bundle PEM de CA vigente
con `--ca-file roots.pem`. Así Go verifica certificados sin buscar emisores
mediante una conexión fuera de la frontera aprobada. El bundle proporcionado
reemplaza las raíces del sistema para ese análisis; la verificación TLS nunca
se desactiva.

```console
go run ./cmd/sentinelhttp scan https://your-authorized-host.example/ --ca-file roots.pem --format json --output before.json --lang es
go run ./cmd/sentinelhttp diff before.json after.json --format terminal --lang es
go run ./cmd/sentinelhttp scan http://127.0.0.1:8080/ --allow-private --trace-redirects --probe-cors --max-redirects 3 --max-requests 7
```

Sin opciones adicionales, `scan` hace un GET. La última línea habilita un
laboratorio local: hasta cuatro GET de la traza y tres muestras CORS sin
credenciales. Cada solicitud atraviesa la misma aprobación de alcance y
conexión verificada. Los destinos privados o loopback se bloquean por defecto;
`--allow-private` los permite y fija las redirecciones al host original. Se
bloquean los saltos HTTPS→HTTP. No hay crawling, inicio de sesión, cookies
enviadas ni pruebas autenticadas.

## Interpretación y privacidad

El JSON versionado reúne evidencia HTTP, TLS, cabeceras de seguridad, cookies,
CSP, CORS y redirecciones dentro de límites explícitos. Cada hallazgo separa
observación, inferencia, confianza y limitaciones. La puntuación considera solo
una respuesta principal capturada y muestra qué dominios pudieron evaluarse.
La falta de evidencia o de hallazgos no demuestra que la aplicación sea segura.

El informe omite rutas, consultas, cuerpos, valores de cookies y valores
`Location` sin procesar. Aun así, orígenes, certificados y nombres de cookies
pueden ser sensibles: protegé los archivos. `diff` compara automáticamente
solo análisis compatibles de la raíz sin consulta del mismo origen y marca
`unknown` cuando no puede probar un cambio. El panel lee archivos locales
validados, pero la validación no autentica su procedencia.

[Contrato del informe](docs/reporting.md) · [Puntuación](docs/scoring.md) ·
[Diff](docs/diff.md) · [Panel](docs/dashboard.md) ·
[Seguridad](docs/security.md).

## Arquitectura y desarrollo

La CLI coordina una captura acotada. `network` es dueño de las conexiones
salientes y valida alcance, DNS y par TCP; `dashboard` solo abre un listener
entrante en loopback. Analizadores, hallazgos, puntuación, informe y diff son
consumidores puros de evidencia. El frontend React/TypeScript está incluido
en el binario Go, sin CDN. Consultá la [arquitectura](docs/architecture.md),
su [autoevaluación](docs/architecture-self-review.md) y el
[caso de portfolio](docs/portfolio.md).

```console
go test ./...
go vet ./...
npm ci --prefix frontend
npm run build --prefix frontend
```

Las pruebas usan resolvers falsos y servicios HTTP/TLS locales, nunca destinos
públicos. CI ejecuta el detector de carreras de Go en Linux y auditorías de
dependencias. La máquina Windows usada en el desarrollo no tiene compilador C
para ejecutar `go test -race` localmente. La presentación admite inglés,
español, ruso y chino simplificado; el JSON no cambia con `--lang`.
[Opciones y códigos de salida](docs/cli.md) ·
[Guía de desarrollo](docs/development.md).
