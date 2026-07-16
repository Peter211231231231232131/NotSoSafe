'use strict';

/*
 * Forzer MCP server (stdio, JSON-RPC 2.0, zero dependencies).
 *
 * Exposes the control-plane as MCP tools so a client (or the agent dev)
 * can drive it "for real" against a live server + agent:
 *   - list_peers      : current mesh
 *   - run_command     : one-shot command on a peer (returns rc + output)
 *   - terminal_start  : open an interactive shell session on a peer
 *   - terminal_input  : send keystrokes / Ctrl-C to a session
 *   - terminal_read   : read buffered terminal output for a session
 *   - terminal_end    : close a session
 *
 * Usage: node mcp-server.js   (env: FORZER_MCP_URL, FORZER_MCP_USER/PASS)
 */

const WebSocket = require('ws');
const readline = require('readline');

const CTRL_URL = process.env.FORZER_MCP_URL ||
  (process.env.FORZER_SERVER ? process.env.FORZER_SERVER.replace(/\/$/, '') : 'ws://127.0.0.1:3000');
const DASH_USER = process.env.FORZER_MCP_USER || process.env.DASH_USER || 'Forgot';
const DASH_PASS = process.env.FORZER_MCP_PASS || process.env.DASH_PASS || 'HelloWorld1!';

let ws = null;
let viewerId = null;
let peers = [];
let reqId = 0;
let pending = {};            // request id -> {resolve, reject, timer}
const termBuffers = {};      // session id -> string
const termExit = {};         // session id -> rc

function connect() {
  return new Promise((resolve, reject) => {
    const url = CTRL_URL.replace(/^http/, 'ws');
    ws = new WebSocket(url);
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'dashboard', user: DASH_USER, pass: DASH_PASS }));
    });
    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }
      if (msg.type === 'dashboard-ready') { viewerId = msg.id; resolve(); }
      else if (msg.type === 'dashboard-auth' && !msg.ok) { reject(new Error(msg.error || 'auth failed')); }
      else if (msg.type === 'map') { peers = msg.peers || []; }
      else if (msg.type === 'command-result') {
        const p = pending[msg.id];
        if (p) { clearTimeout(p.timer); delete pending[msg.id]; p.resolve(msg); }
      }
      else if (msg.type === 'command-error') {
        const p = pending[msg.id];
        if (p) { clearTimeout(p.timer); delete pending[msg.id]; p.reject(new Error(msg.error || 'command failed')); }
      }
      else if (msg.type === 'term-data' && msg.id) {
        termBuffers[msg.id] = (termBuffers[msg.id] || '') + (msg.data ? Buffer.from(msg.data, 'base64').toString() : '');
      }
      else if (msg.type === 'term-exit' && msg.id) {
        termExit[msg.id] = msg.rc;
      }
    });
    ws.on('error', reject);
  });
}

function send(obj, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const id = 'm' + (++reqId);
    const timer = setTimeout(() => { delete pending[id]; reject(new Error('timeout')); }, timeoutMs);
    pending[id] = { resolve, reject, timer };
    obj.id = id;
    ws.send(JSON.stringify(obj));
  });
}

function peerIdByNameOrId(ref) {
  if (!ref) return null;
  const p = peers.find((x) => x.id === ref || x.name === ref);
  return p ? p.id : ref;
}

/* --------------------------- MCP protocol --------------------------- */

const TOOLS = [
  {
    name: 'list_peers',
    description: 'List currently connected mesh peers (id, name, ip).',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'run_command',
    description: 'Run a one-shot command on a peer and return its output + exit code.',
    inputSchema: {
      type: 'object',
      properties: {
        peer: { type: 'string', description: 'peer id or name' },
        command: { type: 'string', description: 'command line to run' },
      },
      required: ['peer', 'command'],
    },
  },
  {
    name: 'terminal_start',
    description: 'Open an interactive shell session on a peer.',
    inputSchema: {
      type: 'object',
      properties: { peer: { type: 'string' }, session: { type: 'string', description: 'optional session id' } },
      required: ['peer'],
    },
  },
  {
    name: 'terminal_input',
    description: 'Send keystrokes (or "\\u0003" for Ctrl-C) to a terminal session.',
    inputSchema: {
      type: 'object',
      properties: { session: { type: 'string' }, data: { type: 'string' } },
      required: ['session', 'data'],
    },
  },
  {
    name: 'terminal_read',
    description: 'Read (and clear) buffered output of a terminal session.',
    inputSchema: { type: 'object', properties: { session: { type: 'string' } }, required: ['session'] },
  },
  {
    name: 'terminal_end',
    description: 'Close a terminal session.',
    inputSchema: { type: 'object', properties: { session: { type: 'string' } }, required: ['session'] },
  },
];

function callTool(name, args) {
  switch (name) {
    case 'list_peers':
      return { content: [{ type: 'text', text: JSON.stringify(peers, null, 2) }] };
    case 'run_command': {
      const to = peerIdByNameOrId(args.peer);
      if (!to) return { content: [{ type: 'text', text: 'peer not found' }], isError: true };
      const id = 'c' + (++reqId);
      return send({ type: 'command', to, id, data: args.command }).then((m) => ({
        content: [{ type: 'text', text: `rc=${m.rc}\n${m.data || ''}` }],
      }));
    }
    case 'terminal_start': {
      const to = peerIdByNameOrId(args.peer);
      if (!to) return { content: [{ type: 'text', text: 'peer not found' }], isError: true };
      const session = args.session || ('s' + (++reqId));
      termBuffers[session] = '';
      delete termExit[session];
      ws.send(JSON.stringify({ type: 'term-start', to, id: session }));
      return { content: [{ type: 'text', text: `session ${session} started on ${to}` }] };
    }
    case 'terminal_input': {
      const b64 = Buffer.from(args.data, 'binary').toString('base64');
      ws.send(JSON.stringify({ type: 'term-input', to: '', id: args.session, data: b64 }));
      return { content: [{ type: 'text', text: 'sent' }] };
    }
    case 'terminal_read': {
      const out = termBuffers[args.session] || '';
      termBuffers[args.session] = '';
      const exited = args.session in termExit ? `(exited rc=${termExit[args.session]})` : '';
      return { content: [{ type: 'text', text: out + exited }] };
    }
    case 'terminal_end': {
      ws.send(JSON.stringify({ type: 'term-end', to: '', id: args.session }));
      delete termBuffers[args.session];
      delete termExit[args.session];
      return { content: [{ type: 'text', text: 'ended' }] };
    }
    default:
      return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
  }
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
let buf = '';

rl.on('line', (line) => {
  buf += line;
  let msg;
  try { msg = JSON.parse(buf); } catch { return; } // wait for full JSON
  buf = '';
  handle(msg);
});

function respond(id, result, error) {
  const o = { jsonrpc: '2.0', id };
  if (error) o.error = error; else o.result = result;
  process.stdout.write(JSON.stringify(o) + '\n');
}

async function handle(msg) {
  try {
    if (msg.method === 'initialize') {
      respond(msg.id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'forzer-mcp', version: '0.1.0' },
      });
    } else if (msg.method === 'tools/list') {
      respond(msg.id, { tools: TOOLS });
    } else if (msg.method === 'tools/call') {
      const res = await callTool(msg.params.name, msg.params.arguments || {});
      respond(msg.id, res);
    } else if (msg.method === 'notifications/initialized' || msg.method === 'ping') {
      // no response required
    } else {
      respond(msg.id, null, { code: -32601, message: 'method not found' });
    }
  } catch (e) {
    respond(msg.id, null, { code: -32603, message: e.message });
  }
}

connect().then(() => {
  // ready; stdin loop already running
}).catch((e) => {
  process.stderr.write('mcp connect error: ' + e.message + '\n');
  process.exit(1);
});
