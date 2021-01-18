import fs from 'fs';
import path from 'path';

export default (() => {
  fs.readdirSync(__dirname)
    .filter((file) => (file.indexOf('.') !== 0) && (file !== 'index.js'))
    .forEach((file) => {
      // eslint-disable-next-line no-unused-expressions
      import(path.join(__dirname, file));
    });
})();
