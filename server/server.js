// API central de Toma de Inventario
// - Usuarios, roles y permisos (los mismos permisos que usa la PWA)
// - Tomas (sede + fecha): el administrador sube UNA vez el Reporte de Inventario y los Items Facturados
// - Cada teléfono descarga esa data, trabaja sin internet y sube su conteo cuando hay conexión
// - Panel central en /admin para ver y consumir toda la información
import express from "express";
import compression from "compression";
import { DatabaseSync } from "node:sqlite";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(DIR, "data");
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(DIR, "..");          // la PWA
const ADMIN_DIR = process.env.ADMIN_DIR || path.join(DIR, "..", "admin");   // el panel
const SESION_DIAS = +process.env.SESSION_DAYS || 30;
fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------- Secreto para firmar sesiones ---------- */
let SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  const f = path.join(DATA_DIR, ".secret");
  if (fs.existsSync(f)) SECRET = fs.readFileSync(f, "utf8").trim();
  else { SECRET = crypto.randomBytes(48).toString("hex"); fs.writeFileSync(f, SECRET, { mode: 0o600 }); }
}

/* ---------- Base de datos (SQLite, un solo archivo en DATA_DIR) ---------- */
const db = new DatabaseSync(path.join(DATA_DIR, "inventario.db"));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  u TEXT PRIMARY KEY, nombre TEXT NOT NULL, rol TEXT NOT NULL DEFAULT 'inv', perm TEXT, sedes TEXT,
  pass TEXT, activo INTEGER NOT NULL DEFAULT 1, tv INTEGER NOT NULL DEFAULT 0, creado INTEGER, ultimo INTEGER);
CREATE TABLE IF NOT EXISTS tomas (
  id TEXT PRIMARY KEY, sede TEXT NOT NULL, fecha TEXT NOT NULL, claves TEXT,
  meta TEXT, meta_ver INTEGER NOT NULL DEFAULT 0,
  inv TEXT, inv_ver INTEGER NOT NULL DEFAULT 0, inv_resumen TEXT,
  cortes TEXT, cortes_ver INTEGER NOT NULL DEFAULT 0,
  creado INTEGER, creado_por TEXT, act INTEGER);
CREATE TABLE IF NOT EXISTS conteos (
  toma TEXT NOT NULL REFERENCES tomas(id) ON DELETE CASCADE, u TEXT NOT NULL, device TEXT NOT NULL,
  data TEXT, lect INTEGER, prod INTEGER, unidades REAL, act INTEGER,
  PRIMARY KEY (toma, u, device));
CREATE TABLE IF NOT EXISTS auditoria (id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER, u TEXT, accion TEXT, detalle TEXT);
`);

const J = s => { try { return s ? JSON.parse(s) : null; } catch { return null; } };
const now = () => Date.now();
const r3 = n => Math.round(n * 1000) / 1000;
const slug = s => String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^A-Za-z0-9]+/g, "_").replace(/^_|_$/g, "") || "x";
const normUser = u => String(u || "").trim().toLowerCase();
function audit(u, accion, detalle) {
  db.prepare("INSERT INTO auditoria (t, u, accion, detalle) VALUES (?, ?, ?, ?)").run(now(), u || "", accion, detalle ? String(detalle).slice(0, 500) : "");
}

/* ---------- Roles y permisos (mismos nombres que en la PWA) ---------- */
const PERMISOS = ["verStockAbierta", "verStockCerrada", "verDifAbierta", "verDifCerrada", "cargar", "exportar", "cerrar", "quitar", "usuarios", "equipo"];
const PERFILES = {
  admin:   { nombre: "Administrador", p: { verStockAbierta: 1, verStockCerrada: 1, verDifAbierta: 1, verDifCerrada: 1, cargar: 1, exportar: 1, cerrar: 1, quitar: 1, usuarios: 1, equipo: 1 } },
  gerente: { nombre: "Gerente",       p: { verStockAbierta: 0, verStockCerrada: 1, verDifAbierta: 0, verDifCerrada: 1, cargar: 1, exportar: 1, cerrar: 0, quitar: 0, usuarios: 0, equipo: 1 } },
  inv:     { nombre: "Inventarista",  p: { verStockAbierta: 0, verStockCerrada: 0, verDifAbierta: 0, verDifCerrada: 0, cargar: 0, exportar: 0, cerrar: 0, quitar: 0, usuarios: 0, equipo: 0 } },
};
function permisos(u) {
  const p = { ...(PERFILES[u.rol] || PERFILES.inv).p, ...(J(u.perm) || {}) }, out = {};
  for (const k of PERMISOS) out[k] = p[k] ? 1 : 0;
  return out;
}
const usuarioPublico = u => ({ u: u.u, nombre: u.nombre, rol: u.rol, perm: permisos(u), permPropio: J(u.perm), sedes: J(u.sedes), activo: !!u.activo, creado: u.creado, ultimo: u.ultimo });

/* ---------- Contraseñas y sesiones ---------- */
function hashPw(pw) { const salt = crypto.randomBytes(16).toString("hex"); return salt + "$" + crypto.scryptSync(String(pw), salt, 32).toString("hex"); }
function checkPw(pw, stored) {
  if (!stored || !stored.includes("$")) return false;
  const [salt, h] = stored.split("$"), x = crypto.scryptSync(String(pw), salt, 32), y = Buffer.from(h, "hex");
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function firmar(o) { const p = Buffer.from(JSON.stringify(o)).toString("base64url"); return p + "." + crypto.createHmac("sha256", SECRET).update(p).digest("base64url"); }
function verificar(tok) {
  const [p, s] = String(tok || "").split(".");
  if (!p || !s) return null;
  const e = crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
  const o = J(Buffer.from(p, "base64url").toString());
  return o && o.exp > now() ? o : null;
}
const getUser = u => db.prepare("SELECT * FROM users WHERE u = ?").get(normUser(u));
const PW_MIN = 4;

// Primer arranque: crea el administrador
if (!db.prepare("SELECT COUNT(*) n FROM users").get().n) {
  const u = normUser(process.env.ADMIN_USER || "admin"), pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString("base64url");
  db.prepare("INSERT INTO users (u, nombre, rol, pass, creado) VALUES (?, ?, 'admin', ?, ?)").run(u, process.env.ADMIN_NAME || "Administrador", hashPw(pw), now());
  console.log(`\n  Usuario administrador creado → usuario: ${u}  contraseña: ${process.env.ADMIN_PASSWORD ? "(la de ADMIN_PASSWORD)" : pw}\n  Cámbiala al entrar al panel.\n`);
}

// Freno simple contra adivinar contraseñas
const fallos = new Map();
function frenado(clave) { const f = fallos.get(clave); return f && f.n >= 8 && now() - f.t < 15 * 60e3; }
function fallo(clave) { const f = fallos.get(clave); fallos.set(clave, f && now() - f.t < 15 * 60e3 ? { n: f.n + 1, t: f.t } : { n: 1, t: now() }); }

/* ---------- App ---------- */
const app = express();
app.set("trust proxy", true);
app.disable("x-powered-by");
app.use(compression());
app.use(express.json({ limit: process.env.BODY_LIMIT || "80mb" }));   // acepta cuerpos gzip (Content-Encoding)
const api = express.Router();
app.use("/api", api);
api.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

function auth(req, res, next) {
  const o = verificar(String(req.get("authorization") || "").replace(/^Bearer\s+/i, ""));
  if (!o || o.typ !== "s") return res.status(401).json({ error: "Sesión vencida: vuelve a entrar" });
  const u = getUser(o.u);
  if (!u || !u.activo || u.tv !== o.tv) return res.status(401).json({ error: "Sesión vencida: vuelve a entrar" });
  req.user = u; req.perm = permisos(u); next();
}
const need = (...ps) => (req, res, next) => ps.some(p => req.perm[p]) ? next() : res.status(403).json({ error: "Tu usuario no tiene permiso para esta acción" });

api.get("/health", (req, res) => res.json({ ok: true, t: now() }));

api.post("/login", (req, res) => {
  const usuario = normUser(req.body?.usuario), pw = String(req.body?.pw || ""), clave = req.ip + "|" + usuario;
  if (frenado(clave)) return res.status(429).json({ error: "Demasiados intentos. Espera 15 minutos." });
  const u = getUser(usuario);
  if (!u || !u.activo || !checkPw(pw, u.pass)) { fallo(clave); return res.status(401).json({ error: "Usuario o contraseña incorrectos" }); }
  fallos.delete(clave);
  db.prepare("UPDATE users SET ultimo = ? WHERE u = ?").run(now(), u.u);
  audit(u.u, "login", req.get("user-agent"));
  res.json({ token: firmar({ typ: "s", u: u.u, tv: u.tv, exp: now() + SESION_DIAS * 864e5 }), user: usuarioPublico(u) });
});
api.get("/me", auth, (req, res) => res.json({ user: usuarioPublico(req.user) }));
api.post("/me/password", auth, (req, res) => {
  const { actual, nueva } = req.body || {};
  if (!checkPw(actual, req.user.pass)) return res.status(400).json({ error: "La contraseña actual no es correcta" });
  if (String(nueva || "").length < PW_MIN) return res.status(400).json({ error: `La contraseña debe tener al menos ${PW_MIN} caracteres` });
  db.prepare("UPDATE users SET pass = ?, tv = tv + 1 WHERE u = ?").run(hashPw(nueva), req.user.u);
  audit(req.user.u, "cambió su contraseña");
  const u = getUser(req.user.u);
  res.json({ token: firmar({ typ: "s", u: u.u, tv: u.tv, exp: now() + SESION_DIAS * 864e5 }), user: usuarioPublico(u) });
});
// Otro usuario autoriza una acción protegida en el teléfono (quitar del conteo, cerrar/reabrir…)
api.post("/autorizar", auth, (req, res) => {
  const usuario = normUser(req.body?.usuario), permiso = String(req.body?.permiso || ""), clave = req.ip + "|" + usuario;
  if (frenado(clave)) return res.status(429).json({ error: "Demasiados intentos. Espera 15 minutos." });
  const u = getUser(usuario);
  if (!u || !u.activo || !checkPw(req.body?.pw, u.pass)) { fallo(clave); return res.status(401).json({ error: "Usuario o contraseña incorrectos" }); }
  if (!PERMISOS.includes(permiso) || !permisos(u)[permiso]) return res.status(403).json({ error: "Ese usuario no tiene permiso para esta acción" });
  audit(u.u, "autorizó " + permiso, "en el teléfono de " + req.user.u);
  res.json({ nombre: u.nombre, grant: firmar({ typ: "g", u: u.u, nombre: u.nombre, perm: permiso, exp: now() + 48 * 3600e3 }) });
});

/* ---------- Usuarios (solo quien tenga el permiso "usuarios") ---------- */
const adminsActivos = () => db.prepare("SELECT * FROM users WHERE activo = 1").all().filter(u => permisos(u).usuarios).length;
function limpiarPerm(perm) { if (!perm || typeof perm !== "object") return null; const o = {}; for (const k of PERMISOS) if (k in perm) o[k] = perm[k] ? 1 : 0; return Object.keys(o).length ? o : null; }
function limpiarSedes(s) { return Array.isArray(s) && s.length ? s.map(String).filter(Boolean) : null; }
api.get("/users", auth, need("usuarios"), (req, res) => res.json({ users: db.prepare("SELECT * FROM users ORDER BY nombre").all().map(usuarioPublico), perfiles: PERFILES, permisos: PERMISOS }));
api.post("/users", auth, need("usuarios"), (req, res) => {
  const b = req.body || {}, u = normUser(b.u);
  if (!/^[a-z0-9._-]{3,}$/.test(u)) return res.status(400).json({ error: "Usuario: mínimo 3 caracteres, sin espacios" });
  if (!String(b.nombre || "").trim()) return res.status(400).json({ error: "Escribe el nombre" });
  if (!PERFILES[b.rol]) return res.status(400).json({ error: "Perfil no válido" });
  if (getUser(u)) return res.status(409).json({ error: "Ese usuario ya existe" });
  if (String(b.pw || "").length < PW_MIN) return res.status(400).json({ error: `La contraseña debe tener al menos ${PW_MIN} caracteres` });
  db.prepare("INSERT INTO users (u, nombre, rol, perm, sedes, pass, activo, creado) VALUES (?, ?, ?, ?, ?, ?, 1, ?)")
    .run(u, b.nombre.trim(), b.rol, JSON.stringify(limpiarPerm(b.perm)), JSON.stringify(limpiarSedes(b.sedes)), hashPw(b.pw), now());
  audit(req.user.u, "creó usuario", u);
  res.json({ user: usuarioPublico(getUser(u)) });
});
api.put("/users/:u", auth, need("usuarios"), (req, res) => {
  const prev = getUser(req.params.u); if (!prev) return res.status(404).json({ error: "No existe" });
  const b = req.body || {};
  const nuevo = { ...prev,
    nombre: b.nombre != null ? String(b.nombre).trim() || prev.nombre : prev.nombre,
    rol: b.rol && PERFILES[b.rol] ? b.rol : prev.rol,
    perm: "perm" in b ? JSON.stringify(limpiarPerm(b.perm)) : prev.perm,
    sedes: "sedes" in b ? JSON.stringify(limpiarSedes(b.sedes)) : prev.sedes,
    activo: "activo" in b ? (b.activo ? 1 : 0) : prev.activo };
  let tv = prev.tv, pass = prev.pass;
  if (b.pw) { if (String(b.pw).length < PW_MIN) return res.status(400).json({ error: `La contraseña debe tener al menos ${PW_MIN} caracteres` }); pass = hashPw(b.pw); tv++; }
  if (!nuevo.activo && prev.activo) tv++;
  // Siempre debe quedar alguien que administre usuarios
  if (permisos(prev).usuarios && prev.activo && (!permisos(nuevo).usuarios || !nuevo.activo) && adminsActivos() < 2)
    return res.status(400).json({ error: "Debe quedar al menos un usuario activo que administre usuarios" });
  db.prepare("UPDATE users SET nombre = ?, rol = ?, perm = ?, sedes = ?, activo = ?, pass = ?, tv = ? WHERE u = ?")
    .run(nuevo.nombre, nuevo.rol, nuevo.perm, nuevo.sedes, nuevo.activo, pass, tv, prev.u);
  audit(req.user.u, "editó usuario", prev.u + (b.pw ? " (contraseña)" : ""));
  res.json({ user: usuarioPublico(getUser(prev.u)) });
});
api.delete("/users/:u", auth, need("usuarios"), (req, res) => {
  const prev = getUser(req.params.u); if (!prev) return res.status(404).json({ error: "No existe" });
  if (prev.u === req.user.u) return res.status(400).json({ error: "No puedes eliminar tu propio usuario" });
  if (permisos(prev).usuarios && prev.activo && adminsActivos() < 2) return res.status(400).json({ error: "Debe quedar al menos un usuario que administre usuarios" });
  db.prepare("DELETE FROM users WHERE u = ?").run(prev.u);
  audit(req.user.u, "eliminó usuario", prev.u);
  res.json({ ok: true });
});
api.get("/auditoria", auth, need("usuarios"), (req, res) => res.json({ items: db.prepare("SELECT * FROM auditoria ORDER BY id DESC LIMIT 300").all() }));

/* ---------- Tomas ---------- */
const metaDe = t => J(t.meta) || {};
const estaCerrada = t => !!metaDe(t).cerrada;
const accesible = (req, t) => { const s = J(req.user.sedes); return !s || s.includes(t.sede); };
const puedeStock = (req, t) => !!(req.perm.verStockAbierta || (req.perm.verStockCerrada && estaCerrada(t)));
const puedeDif = (req, t) => !!(req.perm.verDifAbierta || (req.perm.verDifCerrada && estaCerrada(t)));
const puedeCortes = (req, t) => puedeDif(req, t) || puedeStock(req, t) || req.perm.cargar;
function getToma(req, res) {
  const t = db.prepare("SELECT * FROM tomas WHERE id = ?").get(req.params.id);
  if (!t) { res.status(404).json({ error: "Esta toma ya no existe en el servidor" }); return null; }
  if (!accesible(req, t)) { res.status(403).json({ error: "No tienes acceso a esta sede" }); return null; }
  return t;
}
function tomaPublica(req, t) {
  const m = metaDe(t), r = J(t.inv_resumen), stock = puedeStock(req, t), cortes = J(t.cortes) || [];
  const cond = req.perm.equipo ? "" : " AND u = ?", args = req.perm.equipo ? [t.id] : [t.id, req.user.u];
  const c = db.prepare(`SELECT COUNT(DISTINCT u) usuarios, COUNT(*) equipos, COALESCE(SUM(lect), 0) lect, MAX(act) act FROM conteos WHERE toma = ?${cond}`).get(...args);
  return { id: t.id, sede: t.sede, fecha: t.fecha, claves: J(t.claves) || [], creado: t.creado, creado_por: t.creado_por, act: Math.max(t.act || 0, c.act || 0),
    meta: { cerrada: m.cerrada || null, historial: m.historial || [], tol: m.tol ?? null }, meta_ver: t.meta_ver,
    inv_ver: t.inv_ver, inv_stock: stock, inv: r ? { archivo: r.archivo, t: r.t, n: r.n, empresa: r.empresa, ...(stock ? { unidades: r.unidades } : {}) } : null,
    cortes_ver: puedeCortes(req, t) ? t.cortes_ver : null, n_cortes: cortes.length,
    conteo: { usuarios: c.usuarios, equipos: c.equipos, lect: c.lect } };
}
api.get("/tomas", auth, (req, res) => {
  const l = db.prepare("SELECT * FROM tomas ORDER BY fecha DESC, sede").all().filter(t => accesible(req, t));
  res.json({ tomas: l.map(t => tomaPublica(req, t)), user: usuarioPublico(req.user) });
});
api.get("/tomas/:id", auth, (req, res) => { const t = getToma(req, res); if (t) res.json(tomaPublica(req, t)); });
api.post("/tomas", auth, need("cargar"), (req, res) => {
  const b = req.body || {}, sede = String(b.sede || "").trim(), fecha = String(b.fecha || "");
  if (!sede) return res.status(400).json({ error: "Indica la sede" });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ error: "Indica la fecha (AAAA-MM-DD)" });
  const id = String(b.id || slug(sede) + "_" + fecha);
  const s = J(req.user.sedes); if (s && !s.includes(sede)) return res.status(403).json({ error: "No tienes acceso a esta sede" });
  if (!db.prepare("SELECT 1 FROM tomas WHERE id = ?").get(id)) {
    db.prepare("INSERT INTO tomas (id, sede, fecha, claves, meta, meta_ver, cortes, creado, creado_por, act) VALUES (?, ?, ?, ?, '{}', ?, '[]', ?, ?, ?)")
      .run(id, sede, fecha, JSON.stringify(Array.isArray(b.claves) ? b.claves : []), now(), now(), req.user.u, now());
    audit(req.user.u, "creó toma", id);
  }
  req.params.id = id; const t = getToma(req, res); if (t) res.json(tomaPublica(req, t));
});
api.delete("/tomas/:id", auth, need("cerrar"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  db.prepare("DELETE FROM tomas WHERE id = ?").run(t.id); invCache.delete(t.id);
  audit(req.user.u, "eliminó toma", t.id);
  res.json({ ok: true });
});

// Reporte de Inventario (lo sube el administrador UNA vez; los teléfonos lo descargan).
// Sin permiso de ver existencias se envía sin existencia ni costo: el inventarista cuenta "a ciegas".
const invCache = new Map();
function invPara(t, conStock) {
  let c = invCache.get(t.id);
  if (!c || c.ver !== t.inv_ver) {
    const inv = J(t.inv), ciego = J(t.inv);
    if (ciego) { for (const k in ciego.items) { const it = ciego.items[k]; ciego.items[k] = { cod: it.cod, bc: it.bc, desc: it.desc }; } delete ciego.unidades; ciego.ciego = true; }
    c = { ver: t.inv_ver, full: JSON.stringify({ ver: t.inv_ver, stock: true, inv }), ciego: JSON.stringify({ ver: t.inv_ver, stock: false, inv: ciego }) };
    invCache.set(t.id, c);
  }
  return conStock ? c.full : c.ciego;
}
api.get("/tomas/:id/inv", auth, (req, res) => {
  const t = getToma(req, res); if (!t) return;
  res.type("json").send(invPara(t, puedeStock(req, t)));
});
api.put("/tomas/:id/inv", auth, need("cargar"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  if (estaCerrada(t)) return res.status(423).json({ error: "La toma está cerrada en el servidor" });
  const inv = req.body?.inv;
  if (!inv || typeof inv.items !== "object") return res.status(400).json({ error: "Inventario no válido" });
  const v = now(), resumen = { archivo: inv.archivo, t: inv.t, n: Object.keys(inv.items).length, unidades: inv.unidades, empresa: inv.empresa };
  // Al reemplazar el inventario se borran los Items Facturados (igual que en la app)
  db.prepare("UPDATE tomas SET inv = ?, inv_ver = ?, inv_resumen = ?, cortes = '[]', cortes_ver = ?, act = ? WHERE id = ?")
    .run(JSON.stringify(inv), v, JSON.stringify(resumen), v, v, t.id);
  audit(req.user.u, "subió inventario", `${t.id}: ${inv.archivo} (${resumen.n} productos)`);
  res.json(tomaPublica(req, db.prepare("SELECT * FROM tomas WHERE id = ?").get(t.id)));
});
// Items Facturados (cortes)
api.get("/tomas/:id/cortes", auth, (req, res) => {
  const t = getToma(req, res); if (!t) return;
  if (!puedeCortes(req, t)) return res.status(403).json({ error: "Sin permiso" });
  res.json({ ver: t.cortes_ver, cortes: J(t.cortes) || [] });
});
api.put("/tomas/:id/cortes", auth, need("cargar"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  if (estaCerrada(t)) return res.status(423).json({ error: "La toma está cerrada en el servidor" });
  const cortes = req.body?.cortes;
  if (!Array.isArray(cortes)) return res.status(400).json({ error: "Datos no válidos" });
  if (req.body.base_inv && req.body.base_inv !== t.inv_ver) return res.status(409).json({ error: "El inventario cambió en el servidor; vuelve a cargar los Items Facturados", toma: tomaPublica(req, t) });
  db.prepare("UPDATE tomas SET cortes = ?, cortes_ver = ?, act = ? WHERE id = ?").run(JSON.stringify(cortes), now(), now(), t.id);
  audit(req.user.u, "actualizó Items Facturados", `${t.id}: ${cortes.length} reporte(s)`);
  res.json(tomaPublica(req, db.prepare("SELECT * FROM tomas WHERE id = ?").get(t.id)));
});
// Estado de la toma: cerrar / reabrir / tolerancia. "base" evita que un teléfono con datos viejos deshaga un cierre.
function guardarMeta(req, res, t, nuevo, base, grant) {
  const m = metaDe(t);
  if (!!m.cerrada !== !!nuevo.cerrada) {
    if (base != null && base !== t.meta_ver) return res.status(409).json({ error: "El estado de la toma cambió en el servidor", toma: tomaPublica(req, t) });
    let ok = !!req.perm.cerrar, quien = req.user.nombre;
    if (!ok && grant) { const g = verificar(grant); if (g && g.typ === "g" && g.perm === "cerrar") { ok = true; quien = g.nombre; } }
    if (!ok) return res.status(403).json({ error: "Tu usuario no tiene permiso para cerrar o reabrir tomas", toma: tomaPublica(req, t) });
    m.cerrada = nuevo.cerrada || null;
    m.historial = Array.isArray(nuevo.historial) && nuevo.historial.length >= (m.historial || []).length ? nuevo.historial.slice(-300)
      : [...(m.historial || []), { accion: m.cerrada ? "Cerrada" : "Reabierta", t: now(), usuario: req.user.nombre, autorizo: quien }];
    audit(req.user.u, m.cerrada ? "cerró toma" : "reabrió toma", t.id);
  }
  if (nuevo.tol != null && Number(nuevo.tol) > 0 && (puedeDif(req, t) || req.perm.cerrar)) m.tol = Number(nuevo.tol);
  db.prepare("UPDATE tomas SET meta = ?, meta_ver = ?, act = ? WHERE id = ?").run(JSON.stringify(m), now(), now(), t.id);
  res.json(tomaPublica(req, db.prepare("SELECT * FROM tomas WHERE id = ?").get(t.id)));
}
api.put("/tomas/:id/meta", auth, (req, res) => {
  const t = getToma(req, res); if (!t) return;
  guardarMeta(req, res, t, req.body?.meta || {}, req.body?.base, req.body?.grant);
});
api.post("/tomas/:id/cerrar", auth, need("cerrar"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  const m = metaDe(t); if (m.cerrada) return res.json(tomaPublica(req, t));
  const c = { t: now(), usuario: req.user.nombre, autorizo: req.user.nombre };
  guardarMeta(req, res, t, { ...m, cerrada: c, historial: [...(m.historial || []), { accion: "Cerrada (panel)", ...c }] });
});
api.post("/tomas/:id/reabrir", auth, need("cerrar"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  const m = metaDe(t); if (!m.cerrada) return res.json(tomaPublica(req, t));
  guardarMeta(req, res, t, { ...m, cerrada: null, historial: [...(m.historial || []), { accion: "Reabierta (panel)", t: now(), usuario: req.user.nombre, autorizo: req.user.nombre }] });
});

/* ---------- Conteos: cada teléfono sube su conteo; cada quien ve solo lo suyo ---------- */
api.put("/tomas/:id/conteo", auth, (req, res) => {
  const t = getToma(req, res); if (!t) return;
  const device = String(req.body?.device || "").slice(0, 64), cnt = req.body?.cnt;
  if (!device || !cnt || typeof cnt.conteo !== "object" || !Array.isArray(cnt.log)) return res.status(400).json({ error: "Conteo no válido" });
  const prev = db.prepare("SELECT act FROM conteos WHERE toma = ? AND u = ? AND device = ?").get(t.id, req.user.u, device);
  if (estaCerrada(t)) {
    // Toma cerrada: solo se acepta si no trae lecturas posteriores al cierre (p. ej. un teléfono que estaba sin señal)
    const tc = metaDe(t).cerrada.t || 0;
    if (cnt.log.some(l => l.t > tc)) return res.status(423).json({ error: "La toma está cerrada en el servidor: tus lecturas nuevas no se pueden subir. Pide que la reabran.", toma: tomaPublica(req, t) });
  }
  const vals = Object.values(cnt.conteo).map(Number).filter(n => n);
  db.prepare(`INSERT INTO conteos (toma, u, device, data, lect, prod, unidades, act) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT (toma, u, device) DO UPDATE SET data = excluded.data, lect = excluded.lect, prod = excluded.prod, unidades = excluded.unidades, act = excluded.act`)
    .run(t.id, req.user.u, device, JSON.stringify(cnt), cnt.log.length, vals.length, r3(vals.reduce((a, b) => a + b, 0)), now());
  if (!prev) audit(req.user.u, "empezó a contar", t.id);
  res.json({ ok: true, act: now(), toma: tomaPublica(req, t) });
});
// Conteos del equipo (para consolidar). "since" = solo los que cambiaron después de esa hora.
api.get("/tomas/:id/conteos", auth, need("equipo"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  const since = +req.query.since || 0;
  const keys = db.prepare("SELECT c.u, c.device, c.lect, c.prod, c.unidades, c.act, COALESCE(us.nombre, c.u) nombre FROM conteos c LEFT JOIN users us ON us.u = c.u WHERE c.toma = ? ORDER BY c.act").all(t.id);
  const data = db.prepare("SELECT u, device, data FROM conteos WHERE toma = ? AND act > ?").all(t.id, since).map(r => ({ u: r.u, device: r.device, cnt: J(r.data) }));
  res.json({ keys, data });
});
api.delete("/tomas/:id/conteos/:u/:device", auth, need("cerrar"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  db.prepare("DELETE FROM conteos WHERE toma = ? AND u = ? AND device = ?").run(t.id, req.params.u, req.params.device);
  audit(req.user.u, "descartó conteo", `${t.id}: ${req.params.u} / ${req.params.device}`);
  res.json({ ok: true });
});

// Consolidado para el panel: inventario + suma de todos los conteos (+ existencia final si hay Items Facturados)
api.get("/tomas/:id/consolidado", auth, need("equipo"), (req, res) => {
  const t = getToma(req, res); if (!t) return;
  const inv = J(t.inv), items = inv ? inv.items : {}, stock = puedeStock(req, t), dif = puedeDif(req, t);
  const cortes = J(t.cortes) || [], ult = cortes.length ? cortes[cortes.length - 1] : null;
  const filas = db.prepare("SELECT c.u, c.device, c.data, c.lect, c.prod, c.unidades, c.act, COALESCE(us.nombre, c.u) nombre FROM conteos c LEFT JOIN users us ON us.u = c.u WHERE c.toma = ?").all(t.id);
  const contado = {}, por = {}, raw = {}, t1 = {}, t2 = {};
  const usuarios = filas.map(f => { const cnt = J(f.data) || { conteo: {}, log: [] };
    for (const k in cnt.conteo) { const q = Number(cnt.conteo[k]) || 0; contado[k] = r3((contado[k] || 0) + q); (por[k] = por[k] || {})[f.u] = r3((por[k][f.u] || 0) + q); }
    Object.assign(raw, cnt.raw || {});
    for (const l of cnt.log) { if (!(l.k in t1) || l.t < t1[l.k]) t1[l.k] = l.t; if (!(l.k in t2) || l.t > t2[l.k]) t2[l.k] = l.t; }
    return { u: f.u, nombre: f.nombre, device: f.device, lect: f.lect, prod: f.prod, unidades: f.unidades, act: f.act }; });
  const out = [];
  for (const k of new Set([...Object.keys(items), ...Object.keys(contado)])) {
    const it = items[k], fue = k in contado;
    const x = { k, cod: it ? it.cod : "", bc: it ? it.bc : (raw[k] || k.replace(/^\?/, "")), desc: it ? it.desc : "SIN EXISTENCIA EN SISTEMA",
      contado: fue ? contado[k] : null, por: por[k] || {}, t1: t1[k] || null, t2: t2[k] || null, enInv: !!it };
    if (stock) { x.stock = it ? it.stock : 0; x.costo = it && it.costo != null ? it.costo : null; }
    if (dif && ult && ult.exist) x.final = it ? (k in ult.exist ? ult.exist[k] : it.stock) : 0;
    out.push(x);
  }
  res.json({ toma: tomaPublica(req, t), stock, dif, corte: ult ? { t: ult.t, archivo: ult.archivo, conExist: !!ult.exist } : null, usuarios, filas: out });
});

/* ---------- Archivos: PWA en "/", panel en "/admin" ---------- */
app.get("/config.js", (req, res) => { res.type("js").set("Cache-Control", "no-cache").send(`window.TI_API = ${JSON.stringify(process.env.PUBLIC_API || "api")};\n`); });
const sinCache = { setHeaders: r => r.setHeader("Cache-Control", "no-cache") };
app.use("/admin", express.static(ADMIN_DIR, sinCache));
app.use("/lib", express.static(path.join(PUBLIC_DIR, "lib"), { maxAge: "7d" }));
for (const f of ["index.html", "manifest.json", "sw.js", "icon-192.png", "icon-512.png"])
  app.get("/" + f, (req, res) => res.set("Cache-Control", "no-cache").sendFile(path.join(PUBLIC_DIR, f)));
app.get("/", (req, res) => res.set("Cache-Control", "no-cache").sendFile(path.join(PUBLIC_DIR, "index.html")));
api.use((req, res) => res.status(404).json({ error: "No existe" }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.type === "entity.too.large" ? "El archivo es demasiado grande" : "Error del servidor" });
});

app.listen(PORT, () => console.log(`Toma de Inventario escuchando en http://localhost:${PORT}  (datos en ${DATA_DIR})`));
