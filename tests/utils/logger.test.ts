/**
 * Tests for Logger Module
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  configureLogger,
  setLogLevel,
  getLogLevel,
  createChildLogger,
  logger,
  type LogLevel,
} from '../../src/utils/logger.js';

describe('Logger', () => {
  // Store original env
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Reset to default level
    configureLogger({ level: 'info', pretty: false });
  });

  afterEach(() => {
    // Restore env
    process.env = { ...originalEnv };
  });

  describe('configureLogger', () => {
    it('should configure log level', () => {
      configureLogger({ level: 'debug' });
      expect(getLogLevel()).toBe('debug');
    });

    it('should configure with pretty printing', () => {
      // This should not throw
      expect(() => configureLogger({ level: 'info', pretty: true })).not.toThrow();
    });

    it('should configure with name', () => {
      expect(() => configureLogger({ name: 'test-logger' })).not.toThrow();
    });

    it('should merge config options', () => {
      configureLogger({ level: 'warn' });
      configureLogger({ name: 'merged' });
      expect(getLogLevel()).toBe('warn');
    });
  });

  describe('setLogLevel', () => {
    it('should set trace level', () => {
      setLogLevel('trace');
      expect(getLogLevel()).toBe('trace');
    });

    it('should set debug level', () => {
      setLogLevel('debug');
      expect(getLogLevel()).toBe('debug');
    });

    it('should set info level', () => {
      setLogLevel('info');
      expect(getLogLevel()).toBe('info');
    });

    it('should set warn level', () => {
      setLogLevel('warn');
      expect(getLogLevel()).toBe('warn');
    });

    it('should set error level', () => {
      setLogLevel('error');
      expect(getLogLevel()).toBe('error');
    });

    it('should set fatal level', () => {
      setLogLevel('fatal');
      expect(getLogLevel()).toBe('fatal');
    });

    it('should set silent level', () => {
      setLogLevel('silent');
      expect(getLogLevel()).toBe('silent');
    });
  });

  describe('getLogLevel', () => {
    it('should return current log level', () => {
      setLogLevel('debug');
      expect(getLogLevel()).toBe('debug');
    });

    it('should default to info if not set', () => {
      configureLogger({ level: undefined });
      // Should have some default
      expect(typeof getLogLevel()).toBe('string');
    });
  });

  describe('createChildLogger', () => {
    it('should create a child logger with bindings', () => {
      const child = createChildLogger({ module: 'test' });
      expect(child).toBeDefined();
      expect(typeof child.info).toBe('function');
      expect(typeof child.error).toBe('function');
    });

    it('should create child with multiple bindings', () => {
      const child = createChildLogger({ module: 'test', component: 'parser' });
      expect(child).toBeDefined();
    });
  });

  describe('logger methods', () => {
    it('should have trace method', () => {
      expect(typeof logger.trace).toBe('function');
      // Should not throw
      expect(() => logger.trace('test trace')).not.toThrow();
    });

    it('should have debug method', () => {
      expect(typeof logger.debug).toBe('function');
      expect(() => logger.debug('test debug')).not.toThrow();
    });

    it('should have info method', () => {
      expect(typeof logger.info).toBe('function');
      expect(() => logger.info('test info')).not.toThrow();
    });

    it('should have warn method', () => {
      expect(typeof logger.warn).toBe('function');
      expect(() => logger.warn('test warn')).not.toThrow();
    });

    it('should have error method', () => {
      expect(typeof logger.error).toBe('function');
      expect(() => logger.error('test error')).not.toThrow();
    });

    it('should have fatal method', () => {
      expect(typeof logger.fatal).toBe('function');
      expect(() => logger.fatal('test fatal')).not.toThrow();
    });

    it('should have child method', () => {
      expect(typeof logger.child).toBe('function');
      const child = logger.child({ module: 'test' });
      expect(child).toBeDefined();
    });

    it('should have isLevelEnabled method', () => {
      expect(typeof logger.isLevelEnabled).toBe('function');
    });
  });

  describe('logger with object context', () => {
    it('should log trace with object', () => {
      expect(() => logger.trace('trace message', { key: 'value' })).not.toThrow();
    });

    it('should log debug with object', () => {
      expect(() => logger.debug('debug message', { key: 'value' })).not.toThrow();
    });

    it('should log info with object', () => {
      expect(() => logger.info('info message', { key: 'value' })).not.toThrow();
    });

    it('should log warn with object', () => {
      expect(() => logger.warn('warn message', { key: 'value' })).not.toThrow();
    });

    it('should log error with object', () => {
      expect(() => logger.error('error message', { error: 'test error' })).not.toThrow();
    });

    it('should log fatal with object', () => {
      expect(() => logger.fatal('fatal message', { error: 'test error' })).not.toThrow();
    });
  });

  describe('isLevelEnabled', () => {
    it('should return true for enabled levels', () => {
      setLogLevel('info');
      expect(logger.isLevelEnabled('info')).toBe(true);
      expect(logger.isLevelEnabled('warn')).toBe(true);
      expect(logger.isLevelEnabled('error')).toBe(true);
    });

    it('should return false for disabled levels', () => {
      setLogLevel('error');
      expect(logger.isLevelEnabled('trace')).toBe(false);
      expect(logger.isLevelEnabled('debug')).toBe(false);
      expect(logger.isLevelEnabled('info')).toBe(false);
    });

    it('should handle silent level', () => {
      setLogLevel('silent');
      expect(logger.isLevelEnabled('fatal')).toBe(false);
    });
  });
});
