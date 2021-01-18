import dotenv from 'dotenv';
import session from 'express-session';
import fileStore from 'session-file-store';
import os from 'os';

const env = dotenv.config({ path: '.env' }).parsed || process.env;

const config = {
  app: {
    frontUrl: env.FRONT_URL || 'http://localhost:8080',
    domain: process.env.APP_URL || env.APP_URL || 'http://localhost',
    port: process.env.PORT || env.PORT || 3003,
    url: env.FRONT_URL || `http://localhost:${process.env.PORT || env.PORT || 3003}`,
    salt: env.SALT || 'keyboard cat$$',
    env: env.NODE_ENV || 'development',
  },
  db: {
    url: env.DATABASE_URL || 'mongodb://localhost/node-server',
  },
  logging: {
    level: env.LOGGING_LEVEL || 'debug',
    sentryDSN: env.SENTRY_DSN || '',
  },
  session: {
    store: new (fileStore(session))({ path: os.tmpdir() }),
    secret: env.SALT || 'keyboard cat$$',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false,
      maxAge: 60 * 60 * 1000,
    },
  },
};

if (config.app.env === 'production') {
  config.session.proxy = true;
  config.session.secureProxy = true;
  config.session.cookie.secure = true;
}

export default config;
