import { sanitizeXSS, sanitizeSQL, sanitizeNoSQL, sanitizePath, sanitizeCommand } from '../../src/utils/sanitizer.js';
import { checkForVulnerabilities } from '../../src/config/securityPatterns.js';

describe('sanitizer: malicious input is neutralised', () => {
  test('sanitizeXSS strips script tags and event handlers', () => {
    const out = sanitizeXSS('<script>alert(1)</script><img src=x onerror=alert(1)>hi');
    expect(out).not.toMatch(/<script/i);
    expect(out).not.toMatch(/onerror\s*=/i);
  });
  test('sanitizeSQL defangs keywords and comments', () => {
    const out = sanitizeSQL("x'; DROP TABLE users; --");
    expect(out).toContain('[DROP]'); // keyword is bracketed, not removed
    expect(out).not.toContain('--');
  });
  test('sanitizeNoSQL defangs operators', () => {
    // operator is wrapped in brackets (labelled), not removed
    expect(sanitizeNoSQL('{"$ne":null}')).toContain('[$ne]');
  });
  test('sanitizePath removes traversal', () => {
    expect(sanitizePath('../../etc/passwd')).not.toContain('..');
    expect(sanitizePath('a/../b')).not.toContain('..');
  });
  test('sanitizeCommand output no longer trips command-injection patterns', () => {
    expect(checkForVulnerabilities(sanitizeCommand('a | cat /etc/shadow && rm -rf /'), 'commandInjection')).toEqual([]);
  });
});

describe('sanitizer: benign input unchanged', () => {
  test.each(['Hello world', 'john@example.com', 'Order 12345 shipped'])('%s', (s) => {
    expect(sanitizeXSS(s)).toBe(s);
    expect(sanitizeNoSQL(s)).toBe(s);
    expect(sanitizePath(s)).toBe(s);
  });
  test('non-strings pass through', () => {
    expect(sanitizeSQL(5)).toBe(5);
  });
});
