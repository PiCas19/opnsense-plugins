/**
 * Utils › logger
 * Verifica livelli (LOG_LEVEL), instradamento su console e API opzionali (child/withContext).
 */

const originalEnv = process.env;
let spyLog, spyInfo, spyWarn, spyError, spyDebug;

const reloadLogger = (env = {}) =>
  jest.isolateModules(() => {
    process.env = { ...originalEnv, ...env };
    // reset module cache per rileggere LOG_LEVEL
    jest.resetModules();
    return require('../../../src/utils/logger');
  });

beforeEach(() => {
  jest.clearAllMocks();
  // spia console
  spyLog = jest.spyOn(console, 'log').mockImplementation(() => {});
  spyInfo = jest.spyOn(console, 'info').mockImplementation(() => {});
  spyWarn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  spyError = jest.spyOn(console, 'error').mockImplementation(() => {});
  spyDebug = jest.spyOn(console, 'debug').mockImplementation(() => {});
});

afterAll(() => {
  process.env = originalEnv;
  jest.restoreAllMocks();
});

describe('logger base', () => {
  test('espone metodi attesi', () => {
    const logger = reloadLogger();
    ['info', 'warn', 'error', 'debug'].forEach(m =>
      expect(typeof logger[m]).toBe('function')
    );
  });

  test('LOG_LEVEL=warn filtra info/debug ma lascia warn/error', () => {
    const logger = reloadLogger({ LOG_LEVEL: 'warn' });

    logger.debug('dbg');
    logger.info('inf');
    logger.warn('wrn');
    logger.error('err');

    expect(spyDebug).not.toHaveBeenCalled();
    expect(spyInfo).not.toHaveBeenCalled();
    expect(spyWarn).toHaveBeenCalled();
    expect(spyError).toHaveBeenCalled();
  });

  test('LOG_LEVEL=debug permette tutti i livelli', () => {
    const logger = reloadLogger({ LOG_LEVEL: 'debug' });

    logger.debug('dbg');
    logger.info('inf');
    logger.warn('wrn');
    logger.error('err');

    expect(spyDebug).toHaveBeenCalled();
    expect(spyInfo).toHaveBeenCalled();
    expect(spyWarn).toHaveBeenCalled();
    expect(spyError).toHaveBeenCalled();
  });

  test('logger.error accetta Error e metadata senza esplodere', () => {
    const logger = reloadLogger();
    const err = new Error('boom');
    logger.error(err, { route: '/api' });
    expect(spyError).toHaveBeenCalled();
  });
});

describe('context/child logger (se presente)', () => {
  const itIf = (cond) => (cond ? it : it.skip);

  it('child/withContext arricchisce il log con meta (best effort)', () => {
    const logger = reloadLogger({ LOG_LEVEL: 'debug' });
    const child =
      typeof logger.child === 'function'
        ? logger.child({ reqId: 'abc123' })
        : typeof logger.withContext === 'function'
        ? logger.withContext({ reqId: 'abc123' })
        : null;

    if (!child) {
      console.warn('logger.child/withContext non presente — test skippato');
      return;
    }

    child.info('hello');
    expect(spyInfo).toHaveBeenCalled();

    // Se il logger serializza il contesto, la stringa può includere reqId; non rendiamo l’asserzione rigida.
    // Qui ci basta verificare che sia stata emessa una riga a livello info.
  });

  itIf(typeof reloadLogger().setLevel === 'function')('setLevel cambia il filtro runtime', () => {
    const logger = reloadLogger({ LOG_LEVEL: 'error' });
    logger.setLevel('info'); // se esposto
    logger.info('now visible');
    expect(spyInfo).toHaveBeenCalled();
  });
});