export const errorWrap = (handler) => (...args) => {
  handler(...args).catch(args[args.length - 1]);
};

/**
 * Check your statement and throw an error if falsy
 *
 * @param {Boolean} statement
 * @param {function} errorType
 * @param {String|Object} errorArgs
 */
export const assert = (statement, errorType, ...errorArgs) => {
  if (!statement) {
    throw errorType(...errorArgs);
  }
};
