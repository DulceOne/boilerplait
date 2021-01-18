import Joi from '@hapi/joi';
import { notFound } from '@hapi/boom';
import { models } from 'mongoose';

import { METHODS } from '../../config/constants';
import { assert } from '../../helpers';

export const getUsers = {
  method: METHODS.GET,
  path: '/users',
  // validate middleware supports both functional and object schemas
  // auth: {},
  validate: {
    query: {
      skip: Joi.number().integer().min(0).default(0),
      limit: Joi.number().integer().min(1).default(10),
    },
  },
  async handler(req, res) {
    const { email, password } = req.body;
    const users = await models.User.find({ email, password });
    // const total = await models.User.countDocuments();
    // res.json({ data: users, total });
    res.json(users);
  },
};

export const getUser = {
  method: METHODS.GET,
  path: '/users/:id',
  validate: {
    params: {
      id: Joi.string().required(),
    },
  },
  async handler(req, res) {
    const user = await models.User.findOne({ _id: req.params.id });
    assert(user, notFound, 'User not found');
    res.json({ data: user });
  },
};

export const createUser = {
  method: METHODS.POST,
  path: '/users',
  validate: {
    body: {
      first_name: Joi.string(),
      last_name: Joi.string(),
      email: Joi.string().email({ minDomainSegments: 2 }).required(),
    },
  },
  async handler(req, res) {
    const user = new models.User(req.body);
    await user.save();
    res.json({ data: user });
  },
};

export const updateUser = {
  method: METHODS.PATCH,
  path: '/users/:id',
  validate: {
    params: {
      id: Joi.string().required(),
    },
    body: {
      first_name: Joi.string(),
      last_name: Joi.string(),
      email: Joi.string().email({ minDomainSegments: 2 }),
    },
  },
  async handler(req, res) {
    const user = await models.User.findOne({ _id: req.params.id });
    assert(user, notFound, 'User not found');
    Object.keys(req.body).forEach((param) => {
      user[param] = req.body[param];
      user.markModified(param);
    });
    await user.save();
    res.json({ data: user });
  },
};

export const updateOrCreateUser = {
  method: METHODS.PUT,
  path: '/users/:id',
  validate: {
    params: {
      id: Joi.string().required(),
    },
    body: {
      first_name: Joi.string(),
      last_name: Joi.string(),
      email: Joi.string().email({ minDomainSegments: 2 }).required(),
    },
  },
  async handler(req, res) {
    await models.User.updateOne(
      { _id: req.params.id }, req.body, { upsert: true, setDefaultsOnInsert: true, new: true },
    );
    const user = await models.User.findOne({ _id: req.params.id });
    res.json({ data: user });
  },
};

export const deleteUser = {
  method: METHODS.DELETE,
  path: '/users/:id',
  validate: {
    params: {
      id: Joi.string().required(),
    },
  },
  async handler(req, res) {
    const user = await models.User.findOne({ _id: req.params.id });
    assert(user, notFound, 'User not found');
    await user.delete();
    res.json({ data: user });
  },
};
