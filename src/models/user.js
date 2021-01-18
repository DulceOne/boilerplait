/* eslint-disable func-names */
import { Schema, model } from 'mongoose';
import softDelete from 'mongoose-delete';

export const MODEL_NAME = 'User';

const SCHEMA = {
  first_name: {
    type: String,
    default: '',
  },
  last_name: {
    type: String,
    default: '',
  },
  email: {
    type: String,
  },
  password: {
    type: String,
  },
};

const User = new Schema(SCHEMA, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

User.virtual('displayName').get(function () {
  return (`${this.first_name} ${this.last_name}`).trim();
});

User.methods.toJSON = function () {
  return {
    id: this._id,
    firstName: this.first_name,
    lastName: this.last_name,
    displayName: this.displayName,
    email: this.email,
    role: this.role,
    createdAt: this.created_at,
    updatedAt: this.updated_at,
    deletedAt: this.deleted_at,
  };
};

User.plugin(softDelete, { overrideMethods: ['count', 'countDocuments', 'find', 'findOne'] });

export default model(MODEL_NAME, User);
