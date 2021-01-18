import * as userController from './user';

export default [
  userController.getUsers,
  userController.getUser,
  userController.createUser,
  userController.updateUser,
  userController.updateOrCreateUser,
  userController.deleteUser,
];
