# Toma de Inventario · servidor central

Un solo contenedor sirve todo:

| Ruta | Qué es |
|---|---|
| `/` | La app (PWA) que usan los teléfonos. Funciona sin internet y sincroniza sola. |
| `/admin/` | Panel central: tomas, avance de cada persona, consolidado, Excel, usuarios, actividad. |
| `/api/` | API (usuarios, permisos, tomas, inventario, conteos). |

Datos: un archivo SQLite en el volumen `/data` (respáldalo).

## Cómo funciona

1. **Administrador** crea la toma (sede + fecha) en el panel o en la app.
2. En la app (puede ser en la PC), abre la toma y carga el **Reporte de Inventario** una sola vez → se sube al servidor.
3. Cada **teléfono** entra con su usuario, abre la toma y la descarga. Desde ahí cuenta **sin internet**; su conteo se sube solo cada vez que hay señal (indicador ☁ arriba a la derecha).
4. Al terminar, el administrador carga el **Items Facturados** en la app → se sube y queda disponible.
5. El administrador ve todo consolidado en el panel (`/admin`) y en la app → Cierre (con factores, PDF, ajustes para Plade). Cierra la toma desde cualquiera de los dos.

### Roles

| Perfil | Ve existencias del sistema | Ve resultados | Ve conteo del equipo | Carga reportes | Usuarios |
|---|---|---|---|---|---|
| Inventarista | **Nunca** (el servidor ni se las envía) | No | Solo lo suyo | No | No |
| Gerente | Al cerrar la toma | Al cerrar la toma | Sí | Sí | No |
| Administrador | Siempre | Siempre | Sí | Sí | Sí |

Cada permiso se puede ajustar por persona y se pueden limitar las sedes de cada usuario.

## Publicar la imagen en GHCR

El workflow `.github/workflows/docker.yml` construye y publica `ghcr.io/robertdanielpineda1-ux/toma_inventario:latest` en cada push a `main`/`master`.

```bash
git push origin master
```

Si el paquete queda **privado** (por defecto), en Dokploy necesitas credenciales del registro (paso 2). Para evitarlo: GitHub → tu perfil → Packages → `toma_inventario` → Package settings → *Change visibility* → Public.

## Desplegar en Dokploy

1. **Proyecto → Create Service → Application**.
2. **Provider: Docker**
   - Docker Image: `ghcr.io/robertdanielpineda1-ux/toma_inventario:latest`
   - Si es privado: Registry URL `ghcr.io`, usuario de GitHub y un *Personal Access Token (classic)* con permiso `read:packages`.
3. **Environment**:
   ```
   ADMIN_USER=admin
   ADMIN_PASSWORD=una-clave-segura
   JWT_SECRET=una-cadena-larga-aleatoria
   ```
   `ADMIN_PASSWORD` solo se usa la primera vez (cuando la base está vacía). Si no defines `JWT_SECRET`, se genera uno y se guarda en `/data`.
4. **Advanced → Volumes / Mounts**: tipo *Volume*, nombre `inventario-data`, Mount Path `/data`. (Sin esto se pierden los datos al redesplegar.)
5. **Domains**: tu dominio, Container Port `3000`, HTTPS con Let's Encrypt. **Se necesita HTTPS** para que la cámara y la instalación de la PWA funcionen en los teléfonos.
6. **Deploy**. Entra a `https://tu-dominio/admin/`, cambia la clave del admin y crea los usuarios.

### Redespliegue automático (opcional)

En Dokploy → la aplicación → **Deployments → Webhook URL**, cópiala y guárdala en GitHub → Settings → Secrets and variables → Actions → `DOKPLOY_WEBHOOK`. Cada push publica la imagen y Dokploy la vuelve a desplegar.

### Alternativa: Compose

Dokploy → Create Service → **Compose**, pega `docker-compose.yml` y define `ADMIN_PASSWORD` y `JWT_SECRET` en Environment. Agrega el dominio apuntando al servicio `inventario`, puerto `3000`.

## Respaldo

```bash
docker run --rm -v inventario-data:/data -v "$PWD":/b alpine tar czf /b/inventario-$(date +%F).tgz -C /data .
```

## Desarrollo local

```bash
cd server && npm install && ADMIN_PASSWORD=admin123 npm start
```

App: http://localhost:3000 · Panel: http://localhost:3000/admin/

Si abres `index.html` directo (sin servidor) la app funciona como antes: solo local, con usuarios en el teléfono.

## Variables

| Variable | Por defecto | Uso |
|---|---|---|
| `PORT` | `3000` | Puerto HTTP |
| `DATA_DIR` | `/data` | Dónde se guarda la base SQLite |
| `ADMIN_USER` / `ADMIN_PASSWORD` / `ADMIN_NAME` | `admin` / aleatoria | Administrador inicial (se imprime en el log si no defines la clave) |
| `JWT_SECRET` | se genera | Firma de sesiones |
| `SESSION_DAYS` | `30` | Días que dura la sesión de un teléfono |
| `BODY_LIMIT` | `80mb` | Tamaño máximo de inventario/conteo subido |
