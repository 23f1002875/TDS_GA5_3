// Does the raw path (after $HOME/~ expansion, before resolution) contain a
// literal ".." path segment? Legitimate writes never need one, so any use
// of ".." — even if it would lexically resolve back inside BUILD_DIR — is
// treated as an escape attempt and blocked outright.
function containsDotDotSegment(rawPath) {
  let p = rawPath.trim().replace(/^["']|["']$/g, '');
  p = p.replace(/\$\{HOME\}/g, HOME).replace(/\$HOME/g, HOME);
  if (p === '~') p = HOME;
  else if (p.startsWith('~/')) p = HOME + p.slice(1);
  return p.split(/[\/\\]+/).includes('..');
}

function handleWriteFile(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    return { decision: 'block', reason: 'Malformed write path.' };
  }

  if (containsDotDotSegment(rawPath)) {
    return { decision: 'block', reason: 'Write path uses ".." traversal, which is not permitted.' };
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
