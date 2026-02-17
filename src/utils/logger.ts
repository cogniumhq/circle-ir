/**
 * Centralized logging module using pino.
 *
 * Usage:
 *   import { logger } from './utils/logger.js';
 *   logger.info('Processing file', { file: 'test.java' });
 *   logger.error('Failed to parse', { error: err.message });
 *
 * Log Levels (in order of severity):
 *   - trace: Very detailed debugging
 *   - debug: Debugging information
 *   - info: General information (default for CLI)
 *   - warn: Warnings
 *   - error: Errors
 *   - fatal: Fatal errors
 *   - silent: No logging
 *
 * Configuration:
 *   - Set LOG_LEVEL env var to change level
 *   - Set LOG_FORMAT=json for JSON output (default in non-TTY)
 *   - Set LOG_FORMAT=pretty for human-readable output
 */

import pino, { Logger, LoggerOptions } from 'pino';

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal' | 'silent';

export interface LoggerConfig {
  level?: LogLevel;
  pretty?: boolean;
  name?: string;
}

// Default configuration
const DEFAULT_CONFIG: LoggerConfig = {
  level: (process.env.LOG_LEVEL as LogLevel) || 'info',
  pretty: process.env.LOG_FORMAT === 'pretty' || (process.stdout.isTTY && process.env.LOG_FORMAT !== 'json'),
  name: 'circle-ir',
};

let currentConfig: LoggerConfig = { ...DEFAULT_CONFIG };
let loggerInstance: Logger | null = null;

/**
 * Create pino logger options from config
 */
function createLoggerOptions(config: LoggerConfig): LoggerOptions {
  const options: LoggerOptions = {
    name: config.name,
    level: config.level || 'info',
  };

  // Add pretty printing for TTY or when explicitly requested
  if (config.pretty) {
    options.transport = {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'pid,hostname',
        messageFormat: '{msg}',
        singleLine: true,
      },
    };
  }

  return options;
}

/**
 * Get the singleton logger instance
 */
function getLogger(): Logger {
  if (!loggerInstance) {
    const options = createLoggerOptions(currentConfig);
    // Write to stderr to avoid polluting stdout for CLI tools
    if (options.transport) {
      // When using transport (pino-pretty), specify destination in options
      options.transport.options = {
        ...options.transport.options,
        destination: 2, // stderr file descriptor
      };
      loggerInstance = pino(options);
    } else {
      loggerInstance = pino(options, process.stderr);
    }
  }
  return loggerInstance;
}

/**
 * Configure the logger. Should be called early in application startup.
 * Subsequent calls will reconfigure the logger.
 */
export function configureLogger(config: Partial<LoggerConfig>): void {
  currentConfig = { ...currentConfig, ...config };
  const options = createLoggerOptions(currentConfig);
  // Write to stderr to avoid polluting stdout for CLI tools
  if (options.transport) {
    options.transport.options = {
      ...options.transport.options,
      destination: 2, // stderr file descriptor
    };
    loggerInstance = pino(options);
  } else {
    loggerInstance = pino(options, process.stderr);
  }
}

/**
 * Set the log level dynamically
 */
export function setLogLevel(level: LogLevel): void {
  currentConfig.level = level;
  if (loggerInstance) {
    loggerInstance.level = level;
  }
}

/**
 * Get the current log level
 */
export function getLogLevel(): LogLevel {
  return currentConfig.level || 'info';
}

/**
 * Create a child logger with additional context
 */
export function createChildLogger(bindings: Record<string, unknown>): Logger {
  return getLogger().child(bindings);
}

/**
 * The main logger instance.
 * Use this for all logging throughout the application.
 */
export const logger = {
  /**
   * Log at trace level (most verbose)
   */
  trace: (msg: string, obj?: Record<string, unknown>) => {
    if (obj) {
      getLogger().trace(obj, msg);
    } else {
      getLogger().trace(msg);
    }
  },

  /**
   * Log at debug level
   */
  debug: (msg: string, obj?: Record<string, unknown>) => {
    if (obj) {
      getLogger().debug(obj, msg);
    } else {
      getLogger().debug(msg);
    }
  },

  /**
   * Log at info level (default)
   */
  info: (msg: string, obj?: Record<string, unknown>) => {
    if (obj) {
      getLogger().info(obj, msg);
    } else {
      getLogger().info(msg);
    }
  },

  /**
   * Log at warn level
   */
  warn: (msg: string, obj?: Record<string, unknown>) => {
    if (obj) {
      getLogger().warn(obj, msg);
    } else {
      getLogger().warn(msg);
    }
  },

  /**
   * Log at error level
   */
  error: (msg: string, obj?: Record<string, unknown>) => {
    if (obj) {
      getLogger().error(obj, msg);
    } else {
      getLogger().error(msg);
    }
  },

  /**
   * Log at fatal level (most severe)
   */
  fatal: (msg: string, obj?: Record<string, unknown>) => {
    if (obj) {
      getLogger().fatal(obj, msg);
    } else {
      getLogger().fatal(msg);
    }
  },

  /**
   * Create a child logger with additional context
   */
  child: (bindings: Record<string, unknown>) => createChildLogger(bindings),

  /**
   * Check if a level is enabled
   */
  isLevelEnabled: (level: LogLevel): boolean => {
    return getLogger().isLevelEnabled(level);
  },
};

// Export types for consumers
export type { Logger } from 'pino';
