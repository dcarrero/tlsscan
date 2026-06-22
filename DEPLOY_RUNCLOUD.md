# Despliegue del microservicio Go en RunCloud

RunCloud gestiona PHP/nginx, pero **no instala ni gestiona Go directamente**. La buena
noticia: no lo necesita. Compilas un binario estático en tu máquina (o en CI) y lo corres
en el servidor como un proceso supervisado. RunCloud incluye **Supervisor (supervisord)**,
que es exactamente la herramienta para mantener vivo un demonio arbitrario.

Hay dos enfoques. El recomendado es el A.

---

## Enfoque A — Binario estático + Supervisor de RunCloud (recomendado)

No instalas Go en el servidor en absoluto. Compilas fuera y subes el binario.

### 1. Compilar el binario estático (en tu Mac o en CI)

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -o headerforge-tls ./cmd/headerforge-tls
```

`CGO_ENABLED=0` produce un binario sin dependencias dinámicas: corre en cualquier Ubuntu
sin instalar nada. `-ldflags="-s -w"` lo reduce de tamaño.

### 2. Subir el binario al servidor

```bash
scp headerforge-tls usuario@tu-servidor:/home/runcloud/services/tls/headerforge-tls
ssh usuario@tu-servidor 'chmod +x /home/runcloud/services/tls/headerforge-tls'
```

### 3. Crear un Supervisor Job en el panel de RunCloud

En el dashboard de RunCloud: servidor → **Supervisor** → crear job.

| Campo | Valor |
|-------|-------|
| Label | `headerforge-tls` |
| Username | `runcloud` |
| Binary | `/home/runcloud/services/tls/headerforge-tls` |
| Command | (vacío, o flags si los añades) |
| Numprocs | `1` |
| Auto Start | sí |
| Auto Restart | sí |

> La variable `TLS_SCAN_LISTEN` hace que el servicio escuche en `127.0.0.1:8081` por defecto
> (solo accesible localmente). Si necesitas pasarla, usa un pequeño wrapper script como
> Binary que haga `export TLS_SCAN_LISTEN=127.0.0.1:8081 && exec /ruta/headerforge-tls`.

También puedes crearlo vía API de RunCloud:

```bash
curl --request POST \
  --url https://manage.runcloud.io/api/v3/servers/{serverId}/supervisors \
  --header 'Authorization: Bearer TU_TOKEN' \
  --header 'Content-Type: application/json' \
  --data '{
    "label": "headerforge-tls",
    "username": "runcloud",
    "numprocs": 1,
    "autoStart": true,
    "autoRestart": true,
    "binary": "/home/runcloud/services/tls/headerforge-tls",
    "command": ""
  }'
```

### 4. Que Laravel lo consuma (mismo servidor)

Como el servicio escucha en `127.0.0.1:8081`, tu app Laravel en el mismo servidor lo llama
directo sin exponerlo a internet:

```php
$response = Http::timeout(20)->post('http://127.0.0.1:8081/v1/scan', [
    'host' => 'example.com',
    'port' => 443,
    'check_vulns' => true,
]);
$tls = $response->json();
```

### 5. (Opcional) Si Laravel está en OTRO servidor (Stackscale)

No expongas el 8081 a internet. Dos opciones limpias:
- **Red privada de Stackscale:** el servicio escucha en la IP privada y solo Laravel llega.
  `TLS_SCAN_LISTEN=10.0.0.5:8081`.
- **nginx como reverse proxy interno** con `allow` por IP y autenticación por token compartido.

---

## Enfoque B — Instalar Go en el servidor (solo si vas a compilar allí)

Si prefieres compilar en el propio servidor (no recomendado en producción), instala Go
manualmente (RunCloud no lo gestiona):

```bash
# En el servidor, como root o con sudo
cd /tmp
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
source /etc/profile.d/go.sh
go version
```

Luego clonas el repo, `go build`, y sigues desde el paso 3 del Enfoque A. El binario
resultante es el mismo; por eso el Enfoque A (compilar fuera) es más limpio: el servidor
de producción no necesita el toolchain de Go para nada.

---

## Por qué este modelo encaja con tu infraestructura

- **Stackscale:** el binario estático corre en cualquier VM/LXC de tu red privada sin tocar
  el toolchain. Lo despliegas con un `scp` y un systemd unit (o el Supervisor de RunCloud).
- **Sin lock-in:** Go compila a un único binario portable. Cambiar de servidor es copiar un fichero.
- **Aislamiento:** el servicio TLS vive separado de Laravel; si cae, Laravel degrada
  graciosamente (marca el scan TLS como no disponible) sin tumbar la web.

## Resumen

| | RunCloud gestiona Go | Solución |
|-|---------------------|----------|
| Instalación de Go | No | No hace falta: binario estático compilado fuera |
| Correr el demonio | Sí, vía Supervisor | Supervisor Job apuntando al binario |
| Consumo desde Laravel | — | HTTP a `127.0.0.1:8081` (mismo server) o IP privada |
