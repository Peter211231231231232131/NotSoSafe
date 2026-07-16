'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
// Shared secret a device must present to join the network.
// Override in Render with an env var; never commit a real one.
const SETUP_KEY = process.env.SETUP_KEY || 'changeme';
// Virtual IP range: 100.64.0.0/10 (Carrier-Grade NAT space, safe for overlays).
const IP_PREFIX = [100, 64];

// In-memory state. Render restarts wipe this; fine for an MVP.
// A production build would use a database (Redis/Postgres).
const devices = new Map(); // id -> { id, name, pubkey, ip, ws }
const viewers = new Set(); // dashboard websockets (read-only map consumers)
let networkVersion = 0;     // bumped whenever the peer set changes
let ipCounter = 1;          // .1 reserved; first device gets 100.64.0.2

function assignIp() {
  ipCounter += 1;
  const b = ipCounter % 256;
  const a = Math.floor(ipCounter / 256) % 256;
  return `${IP_PREFIX[0]}.${IP_PREFIX[1]}.${a}.${b}`;
}

function newId() {
  return crypto.randomBytes(8).toString('hex');
}

function peerList() {
  return [...devices.values()].map((d) => ({
    id: d.id,
    name: d.name,
    ip: d.ip,
    pubkey: d.pubkey,
  }));
}

// Push the current mesh map to every connected client.
function broadcastMap() {
  networkVersion += 1;
  const payload = JSON.stringify({
    type: 'map',
    version: networkVersion,
    peers: peerList(),
  });
  for (const d of devices.values()) {
    if (d.ws && d.ws.readyState === 1) d.ws.send(payload);
  }
  for (const v of viewers) {
    if (v.readyState === 1) v.send(payload);
  }
}

// --- HTTP surface (health, info, and the web dashboard) ---
let dashboardHtml = '';
try {
  dashboardHtml = fs.readFileSync(path.join(__dirname, 'public', 'dashboard.html'), 'utf8');
} catch (e) {
  dashboardHtml = '<h1>Forzer dashboard not found</h1>';
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, devices: devices.size, version: networkVersion }));
    return;
  }
  if (url.pathname === '/dashboard' || url.pathname === '/dashboard/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(dashboardHtml);
    return;
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      service: 'forzer-control-plane',
      transport: 'websocket',
      note: 'connect via ws:// (or wss:// behind TLS) and send {type:"register",...}',
      dashboard: '/dashboard',
    }));
    return;
  }
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

// --- WebSocket protocol ---
// Client -> Server messages (JSON):
//   { type: 'register', name, pubkey, setupKey }
//   { type: 'signal',       to, data }   (NAT-traversal candidates)
//   { type: 'command',      to, id, data }   (request a peer to run a command)
//   { type: 'command-result', to, id, data, rc }  (reply to a command)
// Server -> Client messages:
//   { type: 'registered', id, ip, setupKeyValid }
//   { type: 'registered', error }   (on failure; connection is then closed)
//   { type: 'map', version, peers }
//   { type: 'signal', from, data }
//   { type: 'command', from, id, data }
//   { type: 'command-result', from, id, data, rc }
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  // WS-level ping/pong is our heartbeat: a dead socket gets terminated.
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      ws.close();
      return;
    }

    if (msg.type === 'register') {
      handleRegister(ws, msg);
    } else if (msg.type === 'dashboard') {
      // Viewer: receives map broadcasts and can issue commands to peers.
      // Basic login gate so the dashboard can't subscribe without creds.
      const DASH_USER = process.env.DASH_USER || 'Forgot';
      const DASH_PASS = process.env.DASH_PASS || 'HelloWorld1!';
      if (String(msg.user || '') !== DASH_USER ||
          String(msg.pass || '') !== DASH_PASS) {
        ws.send(JSON.stringify({ type: 'dashboard-auth', ok: false,
          error: 'invalid credentials' }));
        return ws.close();
      }
      viewers.add(ws);
      ws.viewerId = newId();
      ws.send(JSON.stringify({ type: 'dashboard-ready', id: ws.viewerId }));
      ws.send(JSON.stringify({ type: 'map', version: networkVersion, peers: peerList() }));
    } else if (ROUTABLE.has(msg.type)) {
      relay(ws, msg);
    }
  });

  ws.on('close', () => {
    if (ws.deviceId && devices.has(ws.deviceId)) {
      devices.delete(ws.deviceId);
      broadcastMap();
    }
    viewers.delete(ws);
  });

  ws.on('error', () => {});
});

function handleRegister(ws, msg) {
  if (ws.deviceId) return; // already registered on this socket
  if (msg.setupKey !== SETUP_KEY) {
    ws.send(JSON.stringify({ type: 'registered', error: 'invalid setup key' }));
    return ws.close();
  }
  const pubkey = String(msg.pubkey || '').trim();
  const name = String(msg.name || 'unnamed').slice(0, 64);
  if (!pubkey) {
    ws.send(JSON.stringify({ type: 'registered', error: 'pubkey required' }));
    return ws.close();
  }

  const id = newId();
  const ip = assignIp();
  devices.set(id, { id, name, pubkey, ip, ws });
  ws.deviceId = id;

  ws.send(JSON.stringify({ type: 'registered', id, ip, setupKeyValid: true }));
  broadcastMap(); // includes the new peer for everyone, incl. itself
}

// Messages routed peer-to-peer by their "to" field. The "from" is
// stamped by the server so a peer can't spoof the sender.
const ROUTABLE = new Set(['signal', 'command', 'command-result',
  'term-start', 'term-data', 'term-input', 'term-end', 'term-exit']);
// Types a dashboard viewer is allowed to originate.
const VIEWER_ROUTABLE = new Set(['command', 'term-start', 'term-input', 'term-end']);

function deliver(ws, payload) {
  if (ws && ws.readyState === 1) ws.send(payload);
}

function relay(ws, msg) {
    // A registered device relays with its own device id as the source.
  if (ws.deviceId) {
    const target = devices.get(String(msg.to || ''));
    // Forward to a peer when the destination is another device.
    if (target && target.ws && target.ws.readyState === 1) {
      const payload = JSON.stringify({
        type: msg.type,
        from: ws.deviceId,
        to: msg.to,
        id: msg.id || null,
        data: msg.data || null,
        rc: typeof msg.rc === 'number' ? msg.rc : undefined,
      });
      target.ws.send(payload);
    }
    // Echo command-result / terminal output back to the dashboard viewer
    // that asked, if any.
    const ECHO_TO_VIEWER = new Set(['command-result', 'term-data', 'term-exit', 'term-end']);
    if (ECHO_TO_VIEWER.has(msg.type) && ws.commandViewer) {
      const v = [...viewers].find((x) => x.viewerId === ws.commandViewer);
      if (v && v.readyState === 1) {
        v.send(JSON.stringify({
          type: msg.type,
          from: ws.deviceId,
          to: msg.to,
          id: msg.id || null,
          data: msg.data || null,
          rc: typeof msg.rc === 'number' ? msg.rc : undefined,
        }));
      }
      if (msg.type === 'command-result' || msg.type === 'term-exit' || msg.type === 'term-end') {
        ws.commandViewer = null;
      }
    }
    return;
  }
  // A dashboard viewer may only originate commands; the server stamps a
  // synthetic from so the peer can reply, and remembers which viewer to
  // route the result back to.
  if (ws.viewerId && VIEWER_ROUTABLE.has(msg.type)) {
    const target = devices.get(String(msg.to || ''));
    if (!target || !target.ws || target.ws.readyState !== 1) {
      deliver(ws, JSON.stringify({ type: 'command-error', id: msg.id || null,
        to: msg.to, error: 'peer not connected' }));
      return;
    }
    const from = 'viewer:' + ws.viewerId;
    target.ws.commandViewer = ws.viewerId;
    deliver(target.ws, JSON.stringify({
      type: msg.type,
      from,
      to: msg.to,
      id: msg.id || null,
      data: msg.data || null,
    }));
    return;
  }
}

// Heartbeat: terminate sockets that stop answering pings.
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(heartbeat));

server.listen(PORT, () => {
  console.log(`Forzer control plane (ws) listening on :${PORT}`);
});
