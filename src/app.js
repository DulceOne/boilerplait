import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import session from 'express-session';
import { connect } from 'mongoose';
import { wrap } from '@hapi/joi';
import router from './router';
import config from './config';
import createLogger from './services/createLogger';
import { errorStatusCodes } from './config/constants';

export const appLogger = createLogger('app');
export const httpLogger = createLogger('http', 'magenta');

process.on('unhandledRejection', (error) => {
  appLogger.error(error);
  appLogger.debug('%o', error);
});

const initApp = () => {
  appLogger.info('⏳  Initializing app...');
  const app = express();

  // use helmet and cors middlewares as simple security
  app.use(helmet());
  app.use(cors({ credentials: true, origin: config.app.frontUrl }));

  // parse application/x-www-form-urlencoded and application/json content types
  app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
  app.use(bodyParser.json());

  // session configuration
  app.use(session(config.session));

  // log all http requests
  app.use((req, res, next) => {
    httpLogger.info(`${req.method} ${req.url}`);
    next();
  });

  // set routers before error handler
  app.use('/api', router);

  // error handling
  app.use((err, req, res, next) => {
    appLogger.debug('%o', err);

    // handle default errors if they are wasn't thrown via boom
    if (errorStatusCodes[err.constructor]) {
      wrap(err, errorStatusCodes[err.constructor]);
    }

    // handle boom errors
    if (err.isBoom) {
      const boomError = err.output;
      return res
        .status(boomError.statusCode || 500)
        .json(Object.assign(
          boomError.payload,
          err.data ? { details: err.data } : null,
        ));
    }

    // handle server errors
    res.status(err.status || 500).json({
      statusCode: err.status || 500,
      error: err.name,
      message: err.message,
    });
  });

  // 404 route
  app.use((req, res) => {
    res.status(404).json({
      statusCode: 404,
      error: 'Not Found',
      message: 'No such route',
    });
  });

  return app;
};

const initDB = () => {
  appLogger.info('⏳  Establishing DB connection...');
  return connect(config.db.url, {
    useCreateIndex: true,
    useNewUrlParser: true,
    poolSize: config.db.poolSize,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
    .then(async (res) => {
      appLogger.info('✅  DB connection established. URI: %s', config.db.url);
      appLogger.info('⌛  Loading models...');
      await import('./models/index.js')
        .then(() => appLogger.info('✅  Models loaded'));
      return res;
    });
};

if (!module.parent) { // Don't allow child process spawning
  initDB()
    .then(() => {
      const app = initApp();
      app.listen(config.app.port, () => {
        appLogger.info(`🚀 App is ready for use. Port: ${config.app.port}; PID: ${process.pid}`);
      });
    })
    .catch((err) => appLogger.error('❌  DB connection failed - %s', err));
}
