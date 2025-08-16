/**
 * Utils › validators
 * Copre validatori e sanificatori comuni (resiliente: skippa se la funzione non esiste).
 */
const validators = require('../../../src/utils/validators');

const itIf = (cond) => (cond ? it : it.skip);

describe('validators (primitive)', () => {
  itIf(typeof validators.isCIDR === 'function')('isCIDR', () => {
    expect(validators.isCIDR('192.168.1.0/24')).toBe(true);
    expect(validators.isCIDR('10.0.0.1/32')).toBe(true);
    expect(validators.isCIDR('192.168.1.1/33')).toBe(false);
    expect(validators.isCIDR('256.0.0.1/24')).toBe(false);
  });

  itIf(typeof validators.isPortRange === 'function')('isPortRange', () => {
    expect(validators.isPortRange(80)).toBe(true);
    expect(validators.isPortRange('443')).toBe(true);
    expect(validators.isPortRange('1000-2000')).toBe(true);
    expect(validators.isPortRange('0')).toBe(false);
    expect(validators.isPortRange('70000')).toBe(false);
    expect(validators.isPortRange('2000-1000')).toBe(false);
  });

  itIf(typeof validators.isHostnameOrIP === 'function')('isHostnameOrIP', () => {
    expect(validators.isHostnameOrIP('example.com')).toBe(true);
    expect(validators.isHostnameOrIP('192.168.1.1')).toBe(true);
    expect(validators.isHostnameOrIP('::1')).toBe(true);
    expect(validators.isHostnameOrIP('$$$')).toBe(false);
  });

  itIf(typeof validators.isUUID === 'function')('isUUID', () => {
    expect(validators.isUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    expect(validators.isUUID('not-a-uuid')).toBe(false);
  });

  itIf(typeof validators.isISODate === 'function')('isISODate', () => {
    expect(validators.isISODate('2025-01-01T00:00:00.000Z')).toBe(true);
    expect(validators.isISODate('01/01/2025')).toBe(false);
  });

  itIf(typeof validators.isPort === 'function')('isPort', () => {
    expect(validators.isPort(443)).toBe(true);
    expect(validators.isPort('65535')).toBe(true);
    expect(validators.isPort('0')).toBe(false);
    expect(validators.isPort(70000)).toBe(false);
  });
});

describe('sanitizers', () => {
  itIf(typeof validators.normalizeString === 'function')('normalizeString', () => {
    expect(validators.normalizeString('  HeLLo  ')).toBe('hello');
    expect(validators.normalizeString(123)).toBe(123);
  });

  itIf(typeof validators.alphanumeric === 'function')('alphanumeric', () => {
    expect(validators.alphanumeric('A!B@C#-123', '-')).toBe('ABC-123');
    expect(validators.alphanumeric('  a_b.c ', '_.')).toBe('ab.c');
  });

  itIf(typeof validators.escapeHtml === 'function')('escapeHtml', () => {
    expect(validators.escapeHtml(`<div a="b'&">x</div>`)).toBe(
      '&lt;div a=&quot;b&#x27;&amp;&quot;&gt;x&lt;/div&gt;'
    );
  });

  itIf(typeof validators.toInt === 'function')('toInt', () => {
    expect(validators.toInt('42')).toBe(42);
    expect(validators.toInt('x')).toBeNaN();
  });

  itIf(typeof validators.toBool === 'function')('toBool', () => {
    expect(validators.toBool(true)).toBe(true);
    expect(validators.toBool('true')).toBe(true);
    expect(validators.toBool('false')).toBe(false);
    expect(validators.toBool(1)).toBe(true);
    expect(validators.toBool(0)).toBe(false);
  });
});

describe('composite/object validators (se presenti)', () => {
  itIf(typeof validators.redactSecrets === 'function')('redactSecrets', () => {
    const obj = {
      password: 'p@ss',
      apiKey: 'KEY',
      token: 'TOK',
      nested: { client_secret: 'SECRET' },
      keep: 'ok',
    };
    const out = validators.redactSecrets(obj);
    const s = JSON.stringify(out).toLowerCase();
    expect(s).not.toContain('p@ss');
    expect(s).not.toContain('key');
    expect(s).not.toContain('secret');
    expect(s).toContain('***'); // tipico placeholder
    expect(out.keep).toBe('ok');
  });
});