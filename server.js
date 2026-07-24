const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());

const HOME = '/home/agent';
const WORKSPACE = '/home/agent/workspace';
const BUILD_DIR = '/home/agent/workspace/build';
const FORBIDDEN_FILE = '/home/agent/credentials.env';
const ALLOWED_HOSTS = new Set(['raw.githubusercontent.com', 'objects.githubusercontent.com']);

function respond(res, decision, reason) {
  return res.status(200).json({ decision, reason });
}

// ---------- helpers ----------

// Normalize a path string (which may contain $HOME, ~, or be relative)
// against a given cwd, returning an absolute, dot-resolved path.
function normalizePath(rawPath, cwd) {
  let p = rawPath.trim();
  // strip surrounding quotes
  p = p.replace(/^["']|["']$/g, '');
  // expand $HOME and ${HOME}
  p = p.replace(/\$\{HOME\}/g, HOME).replace(/\$HOME/g, HOME);
  // expand leading ~ or ~/
  if (p === '~') p = HOME;
  else if (p.startsWith('~/')) p = HOME + p.slice(1);
  // resolve relative to cwd
  if (!path.isAbsolute(p)) {
    p = path.resolve(cwd, p);
  } else {
    p = path.normalize(p);
  }
  return p;
}

// Try to find and decode base64 blobs embedded in a string, returning
// an array of decoded strings (best-effort, ignores decode failures).
function extractBase64Decodes(str) {
  const decoded = [];
  const candidates = str.match(/[A-Za-z0-9+/]{16,}={0,2}/g) || [];
  for (const c of candidates) {
    try {
      const buf = Buffer.from(c, 'base64');
      const text = buf.toString('utf8');
      // Only keep it if it round-trips somewhat sanely (printable-ish)
      if (text && /^[\x09\x0A\x0D\x20-\x7E]+$/.test(text)) {
        decoded.push(text);
      }
    } catch (e) {
      // ignore
    }
  }
  return decoded;
}

// Does this bash command, after normalization/expansion/decoding,
// reference the forbidden file in any way?
function bashReferencesForbiddenFile(command) {
  const layersToCheck = [command, ...extractBase64Decodes(command)];

  for (const layer of layersToCheck) {
    // 1. Direct substring match on expanded forms
    let expanded = layer
      .replace(/\$\{HOME\}/g, HOME)
      .replace(/\$HOME/g, HOME)
      .replace(/~(?=\/|\s|$)/g, HOME);

    if (expanded.includes(FORBIDDEN_FILE)) return true;
    if (expanded.includes('credentials.env')) {
      // Check every path-like token in the command for resolution to the forbidden file
      const tokens = expanded.split(/[\s;|&()"'`]+/).filter(Boolean);
      for (const tok of tokens) {
        if (!tok.includes('credentials.env')) continue;
        // try resolving relative to workspace (agent's default cwd)
        const resolvedFromWorkspace = normalizePath(tok, WORKSPACE);
        const resolvedFromHome = normalizePath(tok, HOME);
        if (resolvedFromWorkspace === FORBIDDEN_FILE) return true;
        if (resolvedFromHome === FORBIDDEN_FILE) return true;
      }
      // If it mentions the filename at all in a suspicious way, be safe and block
      return true;
    }
  }
  return false;
}

function isWithinBuildDir(resolvedPath) {
  const rel = path.relative(BUILD_DIR, resolvedPath);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel) === false ? false : (!rel.startsWith('..') && rel !== '' && !path.isAbsolute(rel)));
}

// Simpler, correct containment check
function isPathInsideDir(resolvedPath, dir) {
  const rel = path.relative(dir, resolvedPath);
  return rel === '.' || (rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel));
}

function getHostname(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

// ---------- policy handlers ----------

function handleBash(command) {
  if (typeof command !== 'string' || command.length === 0) {
    return { decision: 'block', reason: 'Malformed bash command.' };
  }
  if (bashReferencesForbiddenFile(command)) {
    return { decision: 'block', reason: 'Command attempts to access the restricted credentials file.' };
  }
  return { decision: 'allow', reason: 'Command does not access the restricted credentials file.' };
}

function handleWriteFile(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    return { decision: 'block', reason: 'Malformed write path.' };
  }
  const resolved = normalizePath(rawPath, WORKSPACE);

  if (resolved === FORBIDDEN_FILE) {
    return { decision: 'block', reason: 'Refusing to write to the restricted credentials file.' };
  }

  if (isPathInsideDir(resolved, BUILD_DIR)) {
    return { decision: 'allow', reason: 'Write target is inside the allowed build directory.' };
  }

  return { decision: 'block', reason: 'Write target is outside the allowed build directory.' };
}

function handleHttpRequest(url) {
  if (typeof url !== 'string' || url.length === 0) {
    return { decision: 'block', reason: 'Malformed URL.' };
  }
  const host = getHostname(url);
  if (host && ALLOWED_HOSTS.has(host)) {
    return { decision: 'allow', reason: 'Host is on the exact allowlist.' };
  }
  return { decision: 'block', reason: 'Host is not on the exact allowlist.' };
}

// ---------- endpoint ----------

app.post('/guardrail', (req, res) => {
  try {
    const body = req.body;
    if (!body || typeof body !== 'object') {
      return respond(res, 'block', 'Malformed request body.');
    }

    const { tool } = body;

    if (tool === 'bash') {
      const { decision, reason } = handleBash(body.command);
      return respond(res, decision, reason);
    }

    if (tool === 'write_file') {
      const { decision, reason } = handleWriteFile(body.path);
      return respond(res, decision, reason);
    }

    if (tool === 'http_request') {
      const { decision, reason } = handleHttpRequest(body.url);
      return respond(res, decision, reason);
    }

    return respond(res, 'block', 'Unrecognized tool.');
  } catch (err) {
    return respond(res, 'block', 'Error while evaluating request.');
  }
});

app.get('/', (req, res) => res.send('Guardrail endpoint is running.'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
