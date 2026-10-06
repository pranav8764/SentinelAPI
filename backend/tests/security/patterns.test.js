import { checkForVulnerabilities, getThreatLevel } from '../../src/config/securityPatterns.js';

const types = (input, type) => [...new Set(checkForVulnerabilities(input, type).map(v => v.type))];

describe('securityPatterns: true positives', () => {
  test.each([
    ['sqlInjection', "1 UNION SELECT username, password FROM users"],
    ['sqlInjection', "x'; DROP TABLE users; --"],
    ['xss', '<script>alert(1)</script>'],
    ['xss', '<img src=x onerror=alert(1)>'],
    ['xss', 'javascript:alert(document.cookie)'],
    ['nosqlInjection', '{"username":{"$ne":null}}'],
    ['nosqlInjection', '{"$where":"function(){return true}"}'],
    ['commandInjection', 'file.txt | cat /etc/shadow'],
    ['commandInjection', 'x && rm -rf /'],
    ['commandInjection', '$(whoami)'],
    ['pathTraversal', '../../etc/passwd'],
    ['pathTraversal', '..\\..\\windows\\system32'],
    ['pathTraversal', '%2e%2e%2f%2e%2e%2fsecret'],
  ])('%s: %s', (type, payload) => {
    expect(types(payload, type)).toContain(type);
  });

  test('repeated calls give the same result (no /g lastIndex statefulness)', () => {
    const a = checkForVulnerabilities('<script>alert(1)</script>', 'xss').length;
    const b = checkForVulnerabilities('<script>alert(1)</script>', 'xss').length;
    expect(a).toBeGreaterThan(0);
    expect(b).toBe(a);
  });
});

// KNOWN FALSE NEGATIVE: classic tautology without a trailing comment is not detected
// (pattern 2 needs 4 quotes, pattern 3 needs `--`). Flip to test() once fixed.
test.failing("sqlInjection: ' OR '1'='1 (known gap)", () => {
  expect(types("' OR '1'='1", 'sqlInjection')).toContain('sqlInjection');
});

describe('securityPatterns: true negatives', () => {
  test.each([
    'Hello, how are you today?',
    'john.doe@example.com',
    'Please select a book from the shelf',
    'Price is $5 with 10% off',
    'path/to/file.txt',
    'The quick brown fox jumps over the lazy dog',
    '555-123-4567',
    'a=1&b=2',
  ])('not flagged: %s', (input) => {
    expect(checkForVulnerabilities(input)).toEqual([]);
  });

  test('non-string / empty input returns []', () => {
    expect(checkForVulnerabilities(null)).toEqual([]);
    expect(checkForVulnerabilities(42)).toEqual([]);
    expect(checkForVulnerabilities('')).toEqual([]);
  });
});

describe('getThreatLevel', () => {
  test('maps highest severity, low when empty', () => {
    expect(getThreatLevel([])).toBe('low');
    expect(getThreatLevel([{ severity: 'medium' }, { severity: 'high' }])).toBe('high');
    expect(getThreatLevel([{ severity: 'high' }, { severity: 'critical' }])).toBe('critical');
    expect(getThreatLevel([{ severity: 'medium' }])).toBe('medium');
  });

  test('real payload reaches critical', () => {
    expect(getThreatLevel(checkForVulnerabilities("x'; DROP TABLE users; --"))).toBe('critical');
  });
});
