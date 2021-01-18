## Express + Mongo implementation
This is a basic example of express + mongo application with some additional packages:

- `Joi` for request validation. See validate middleware and handler methods to see how it's working
- `mongoose` is ORM to easily manipulate Mongo DB
- `mongoose-delete` is a bunch of tools to maintain 'soft delete' logic
- `boom` for http error objects

## How to setup?

- Clone repo
- `npm i -g yarn`
- `yarn`

You can find node and npm versions in `package.json`

## How to run application?

1. Development: 
    - `yarn dev`
2. Production:
    - `yarn build`
    - `yarn start`
