/**
 * Utils › helpers
 * Copre funzioni comuni (sleep, retry, withTimeout, deepMerge, pick/omit, uniqBy, ecc.)
 * I test sono condizionali: skippano se la funzione non esiste nell’implementazione.
 */
jest.useFakeTimers();
jest.spyOn(global, 'setTimeout');

const helpers = require('../../../src/utils/helpers');
const itIf = (cond) => (cond ? it : it.skip);

describe('helpers', () => {
  itIf(typeof helpers.sleep === 'function')('sleep attende ~ms', async () => {
    const p = helpers.sleep(200);
    // avanza il timer
    jest.advanceTimersByTime(200);
    await p;
    expect(setTimeout).toHaveBeenCalled();
  });

  itIf(typeof helpers.retryAsync === 'function')('retryAsync ritenta e poi risolve', async () => {
    let attempts = 0;
    const work = jest.fn(async () => {
      attempts++;
      if (attempts < 3) throw new Error('fail');
      return 'ok';
    });

    const promise = helpers.retryAsync(work, { retries: 5, delayMs: 50 });
    // scarica i timer (se usi delay)
    jest.advanceTimersByTime(50 * 2);
    const res = await promise;

    expect(res).toBe('ok');
    expect(work).toHaveBeenCalledTimes(3);
  });

  itIf(typeof helpers.withTimeout === 'function')('withTimeout risolve entro deadline e rifiuta se scade', async () => {
    // caso OK
    let resolveFn;
    const slow = new Promise((res) => (resolveFn = res));
    const okP = helpers.withTimeout(slow, 1000);
    jest.advanceTimersByTime(999); // non scaduto
    resolveFn('done');
    await expect(okP).resolves.toBe('done');

    // caso TIMEOUT
    const never = new Promise(() => {});
    const toP = helpers.withTimeout(never, 500);
    jest.advanceTimersByTime(500);
    await expect(toP).rejects.toThrow(/timeout/i);
  });

  itIf(typeof helpers.deepMerge === 'function')('deepMerge unisce oggetti annidati', () => {
    const a = { a: 1, nest: { x: 1, y: 1 }, arr: [1] };
    const b = { b: 2, nest: { y: 2, z: 3 }, arr: [2] };
    const out = helpers.deepMerge(a, b);
    expect(out).toEqual({
      a: 1,
      b: 2,
      nest: { x: 1, y: 2, z: 3 },
      arr: [2], // dipende dall’impl.: qui ultima vince
    });
  });

  itIf(typeof helpers.pick === 'function')('pick estrae solo le chiavi richieste', () => {
    const obj = { a: 1, b: 2, c: 3 };
    expect(helpers.pick(obj, ['a', 'c'])).toEqual({ a: 1, c: 3 });
  });

  itIf(typeof helpers.omit === 'function')('omit rimuove le chiavi indicate', () => {
    const obj = { a: 1, b: 2, c: 3 };
    expect(helpers.omit(obj, ['b'])).toEqual({ a: 1, c: 3 });
  });

  itIf(typeof helpers.toArray === 'function')('toArray converte in array', () => {
    expect(helpers.toArray(1)).toEqual([1]);
    expect(helpers.toArray([1, 2])).toEqual([1, 2]);
    expect(helpers.toArray(null)).toEqual([]);
  });

  itIf(typeof helpers.uniqBy === 'function')('uniqBy deduplica per chiave/selector', () => {
    const arr = [{ id: 1 }, { id: 1 }, { id: 2 }];
    const out = helpers.uniqBy(arr, (x) => x.id);
    expect(out).toEqual([{ id: 1 }, { id: 2 }]);
  });

  itIf(typeof helpers.parseNumber === 'function')('parseNumber gestisce basi e fallback', () => {
    expect(helpers.parseNumber('42')).toBe(42);
    expect(helpers.parseNumber('0x10')).toBe(16);
    expect(helpers.parseNumber('nope', 7)).toBe(7);
  });

  itIf(typeof helpers.safeJSONParse === 'function')('safeJSONParse restituisce default su errore', () => {
    expect(helpers.safeJSONParse('{"a":1}')).toEqual({ a: 1 });
    expect(helpers.safeJSONParse('{oops}', { a: 0 })).toEqual({ a: 0 });
  });

  itIf(typeof helpers.safeJSONStringify === 'function')('safeJSONStringify non esplode con cicli', () => {
    const a = {}; a.self = a;
    const s = helpers.safeJSONStringify(a);
    expect(typeof s).toBe('string');
    expect(s.length).toBeGreaterThan(0);
  });

  itIf(typeof helpers.maskToken === 'function')('maskToken/redact maschera valori sensibili', () => {
    expect(helpers.maskToken('abcd1234efgh')).toMatch(/^ab\*+\w{2}$/i);
  });

  itIf(typeof helpers.hashString === 'function')('hashString produce digest deterministico', async () => {
    const h1 = await helpers.hashString('hello');
    const h2 = await helpers.hashString('hello');
    expect(h1).toBe(h2);
    expect(typeof h1).toBe('string');
  });
});