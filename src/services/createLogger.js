import { createLogger, format, transports } from 'winston';
import {
  grey, green, cyan, blue, magenta, yellow, red,
} from 'colors';

import config from '../config';

const {
  colorize, combine, timestamp, label, printf, splat,
} = format;

/**
 * Available logger colors
 *
 * @readonly
 * @enum {string}
 */
const AVAILABLE_COLORS = {
  grey,
  green,
  cyan,
  blue,
  magenta,
  yellow,
  red,
};

const logFormat = (color) => printf(
  (info) => `${grey(info.timestamp)} ${color(`[${info.label}|${info.level}]`)}: ${info.message}`,
);

const transport = ([
  new transports.Console(),
  (config.logging.level === 'error') ? new transports.Console({ level: 'info' }) : null,
]).filter((item) => item);

/**
 * Get logger instance
 *
 * @param {String} loggerLabel
 * @param {('grey'|'green'|'cyan'|'blue'|'magenta'|'yellow'|'red')} loggerColor
 */
export default (loggerLabel, loggerColor = 'green') => createLogger({
  format: combine(
    colorize(),
    splat(),
    label({ label: loggerLabel }),
    timestamp(),
    logFormat(AVAILABLE_COLORS[loggerColor]),
  ),
  stderrLevels: ['error'],
  level: config.logging.level,
  transports: transport,
});
