import jwt from 'jsonwebtoken';

import { unauthorized } from '@hapi/boom';
import { errorWrap } from '../helpers';
import config from '../config';

export default function auth(schema) {
  return errorWrap(async (req, res, next) => {
    const token = req.headers['x-access-token'] || req.cookie['x-access-token'];

    if (!token) {
      return unauthorized();
    }
    const user = jwt.verify(token, config.secret, (err, user) => {
      if (err) {
        return unauthorized('Bad access token');
      }
      req.user = user;
    });
    next();
  });
}
