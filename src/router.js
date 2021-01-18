import glob from 'glob';
import path from 'path';
import { Router } from 'express';

import auth from './middlewares/auth';
import validate from './middlewares/validate';
import { errorWrap } from './helpers';
import { METHODS } from './config/constants';

const router = Router();

// Defines all middlewares and error wrappers and pushing forward to handle method
function addRoute(route, callbacks = []) {
  const method = (route.method || METHODS.GET).toLowerCase();
  if (route.before) callbacks.push(route.before); // Do something before main handler method
  if (route.validate) callbacks.push(validate(route.validate)); // Data validation middleware
  if (route.auth) callbacks.push(auth());
  callbacks.push(errorWrap(route.handler));
  router[method](route.path, ...callbacks);
}

// Resolve and add all defined routes
glob.sync(`${__dirname}/controllers/**/*.routes.js`)
  .forEach((file) => {
    // eslint-disable-next-line global-require,import/no-dynamic-require
    const routes = require(path.resolve(file)).default;
    routes.forEach((route) => addRoute(route));
  });

export default router;
