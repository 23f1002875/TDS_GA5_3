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

// ---------- path helpers ----------

function stripTrailingSlash(p) {
  if (p.length > 1 && p.endsWith(path.sep)) {
    return p.slice(0, -1);
  }
  return p;
}

function normalizePath(rawPath, cwd) {
  let p = rawPath.trim();
  p = p.replace(/^["']|["']$/g, ''); // strip surrounding quotes
  p = p.replace(/\\/g, '/'); // treat backslashes as path separators too
  p = p.replace(/\$\{HOME\}/g, HOME).replace(/\$HOME/g, HOME);
  if (p === '~') p = HOME;
  else if (p.startsWith('~/')) p = HOME + p.slice(1);
  p = path.resolve(cwd, p);
  return p;
}

function isPathInsideOrEqual(resolvedPath, dir) {
  const normDir = stripTrailingSlash(path.resolve(dir));
  const normPath = stripTrailingSlash(path.resolve(resolvedPath));
  if (normPath === normDir) return true;
  const rel = path.relative(normDir, normPath);
  return rel !== '' && !rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel);
}

// ---------- bash forbidden-file detection ----------

function extractBase64Decodes(str) {
  const decoded = [];
  const candidates = str.match(/[A-Za-z0-9+/]{16,}={0,2}/g) || [];
  for (const c of candidates) {
    try {
      const text = Buffer.from(c, 'base64').toString('utf8');
      if (text && /^[\x09\x0A\x0D\x20-\x7E]+$/.test(text)) decoded.push(text);
    } catch (e) { /* ignore */ }
  }
  return decoded;
}

function tokenize(command) {
  return command
    .split(/[\s;|&()"'`<>]+/)
    .map(t => t.trim())
    .filter(Boolean);
}

function commandLayerHitsForbiddenFile(layer) {
  const expanded = layer
    .replace(/\$\{HOME\}/g, HOME)
    .replace(/\$HOME/g, HOME)
    .replace(/~(?=\/|\s|$)/g, HOME);

  if (expanded.includes(FORBIDDEN_FILE)) return true;
  if (!expanded.includes('credentials.env')) return false;

  const tokens = tokenize(expanded);
  for (const tok of tokens) {
    if (!tok.includes('credentials.env')) continue;
    const candidateCwds = [WORKSPACE, HOME];
    for (const cwd of candidateCwds) {
      if (normalizePath(tok, cwd) === FORBIDDEN_FILE) return true;
    }
  }
  return false;
}

function bashReferencesForbiddenFile(command) {
  const layers = [command, ...extractBase64Decodes(command)];
  return layers.some(commandLayerHitsForbiddenFile);
}

// ---------- host helper ----------

function getHostname(urlStr) {
  try {
    return new URL(urlStr).hostname.toLowerCase();
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

  if (isPathInsideOrEqual(resolved, BUILD_DIR)) {
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
