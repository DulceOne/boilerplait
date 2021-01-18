import Joi from '@hapi/joi';
import { notFound } from '@hapi/boom';
import { models } from 'mongoose';
import jwt from 'jsonwebtoken';

import { METHODS } from '../../config/constants';
import { assert } from '../../helpers';

export const login = {
  method: METHODS.POST,
  path: '/login',
  // validate middleware supports both functional and object schemas
  validate: {
    body: {
      email: Joi.number().integer().min(0).default(0),
      password: Joi.number().integer().min(1).default(10),
    },
  },
  async handler(req, res) {
    const { email, password } = req.body;
    const users = await models.User.find({ email, password });
    if (!users) {
      return notFound('User is not found');
    }
    const token = jwt.sign({
      exp: Math.floor(Date.now() / 1000) + (60 * 60),
    });

    res.json();
  },
};

export const register = {
  method: METHODS.POST,
  path: '/register',
  validate: {
    body: {
      email: Joi.string().required(),
      password: Joi.string().required(),
      name: Joi.string().required(),
    },
  },
  async handler(req, res) {
    const user = await models.User.findOne({ _id: req.params.id });
    assert(user, notFound, 'User not found');
    res.json({ data: user });
  },
};
