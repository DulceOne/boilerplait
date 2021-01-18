import Joi from '@hapi/joi';
import { badRequest } from '@hapi/boom';
import { errorWrap } from '../helpers';

// request validation middleware
export default function validate(schema) {
  return errorWrap(async (req, res, next) => {
    if (typeof schema.params === 'object') {
      const validation = typeof schema.params.validate === 'function'
        ? schema.params.validate(req.params, { abortEarly: false })
        : Joi.object(schema.params).validate(req.params, { abortEarly: false });
      if (validation.error) {
        throw badRequest('Invalid params', validation.error.details);
      }
      req.params = validation.value;
    }

    if (typeof schema.query === 'object') {
      const validation = typeof schema.query.validate === 'function'
        ? schema.query.validate(req.query, { abortEarly: false })
        : Joi.object(schema.query).validate(req.query, { abortEarly: false });
      if (validation.error) {
        throw badRequest('Invalid query', validation.error.details);
      }
      req.query = validation.value;
    }

    if (typeof schema.body === 'object') {
      const validation = typeof schema.body.validate === 'function'
        ? schema.body.validate(req.body, { abortEarly: false })
        : Joi.object(schema.body).validate(req.body, { abortEarly: false });
      if (validation.error) {
        throw badRequest('Invalid query', validation.error.details);
      }
      req.body = validation.value;
    }

    next();
  });
}
