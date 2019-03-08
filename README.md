# nest-user-auth

## Next tasks

Add email verification when a user registers.

## Purpose

The goal of this project is to provide code examples to integrate the technologies used since I had a rough time finding good documenation compared to previous projects in Django. If this project helps you, please add a star!

This is a boiler plate project to start with user authentication. Adding other GraphQL models to this project will be easy following the same structure. User auth has always been the hardest and most common thing to implement, so that is what is implemented in this project. Feel free to throw spears at this project or recommend updates. Standard disclaimer: In no way has this been vetted by security experts.

## Technologies

This project is built using MongoDB with Mongoose for the database. NestJS is used as teh framework. GraphQL, Apollo Server, and `@nestjs/graphql` are used for the API. Passport is used for authentication and the strategy is Passport-JWT. Nodemailer is used for email password reset. Joi is used to validate the environment file.

## Model Management

The goal is to have one truth point for the models. That is the `*.types.graphql` files. They contain the GraphQL schema. `@nestjs/graphql` creates `graphql.classes.ts` file to match the GraphQL schema. These classes are used as the base class for the Mongoose Schema and in place of DTOs. Of note, I'd like to use the IMutation and IQuery methods in the resolvers instead of replicating them, but that doesn't seem possible right now.

Username is the primary field to identify a user in a request. Initially username or email were accepted, but for simplicity the schema moved to only username. Both are in the JWT data. Email could be used too. Both are unique.

The database stores a unique lowercase value for both username and email. This is to lookup the user's username or email without case being a factor. Lowercase username and email are also unique, so user@Email.com and user@email.com can't both register. The normal cased version is used for everything but lookup. GraphQL Schemas are not aware lowercase values exist intentionally.

The database handles creating the lowercase value with hooks for `save` and `findOneAndUpdate`.

## Usage

Ensure a MongoDB server is running locally.

To use email, register with any dedicated SMTP server. Gmail doesn't let you change your from address and has other limitations. Mailgun is recommended and works out of the box after you register. With mailgun use their SMTP service, not the API.

Add a `development.env` to the root of your project.

```env
MONGO_URI=mongodb://localhost:27017/user-auth
JWT_SECRET=someSecret
EMAIL_SERVICE=Mailgun
EMAIL_USERNAME=email@mailgun.com
EMAIL_PASSWORD=emailSMTPpassword
EMAIL_FROM=from@somedomain.com
```

Optional Parameters:

`JWT_EXPIRES_IN` Seconds until token expires. If not set, there will be no expiration.

Start the server

`npm install`
`npm run start`

Add a user via the graphql playground or your frontend.

`http://localhost:3000/graphql`

Update that user's Document to have the string `admin` in the permissions array. MongoDB Compass is a great tool to modify fields. That user can now add the admin permission or remove the admin permission to or from other users.

The UsersService `update` method will update any fields which are valid and not duplicates, even if others are invalid or duplicates.

Users can change their `username`, `password`, `email`, or `enabled` status via a mutation. Changing their username will make their token unusable (it won't authenticate when the user presenting the token's username is checked against the token's username). This may or may not be the desired behavior. If using on a front end, make it obvious that you can change your username and it'll log the user out (front end must get a new token via logging in).

If a user sets `enabled` to `false` on their account, they cannot log back in (because it is disabled), only an admin can change it back.

Because you can change both unique properties username and email, \_id should be used for many-to-many relationships.

See `test/users.e2e-spec.ts` for expected results to mutations and queries.

### Environments

Add a `test.env` file which contains a different MONGO_URI that `development.env`. See the testing section for details.

Add any other environments for production and test. The environment variable `NODE_ENV` is used to determine the correct environment to work in. The program defaults to `development` if there is not a `NODE_ENV` environment variable set. For example, if the configuration is stored in `someEnv.env` file in production then set the `NODE_ENV` environment variable to `someEnv`. This can be done through package.json scripts, local environment variables, or your launch.json configuration in VS Code. If you do nothing, it will look for `development.env`. Do not commit this file.

### Authentication

Add the token to your headers `{"Authorization": "Bearer eyj2aGc..."}` to be authenticated via the JwtAuthGuard.

If a user's account property `enabled` is set to false, their token will no longer authenticate. Many critiques of JWTs vs. session based authentication solutions are that a JWT cannot be invalidated once issued. While that is true, no request will authenticate with a valid JWT while the account associated with the token's `enabled` field is false. An admin or the user can set that field via an update.

Admin must be set manually as a string in permissions for the first user (add `admin` to the permissions array). That person can then add admin to other users via a mutation. Permissions is an array of strings so that other permissions can be added to allow custom guards.

Users can modify or view their own data. Admins can do anything except refresh another user's token, which would allow the admin to impersonate that user.

The `UsernameEmailGuard` compares the user's email or username with the same field in a query. If any query or mutation in the resolver has `doAnythingWithUser(username: string)` or `doAnythingWithUser(email: string)` and that email / username matches the user which is requesting the action, it will be approved. Username and email are unique, and the user has already been verified via JWT.

The `UsernameEmailAdminGuard` is the same as the `UsernameEmailGuard` except it also allows admins.

The `AdminGuard` only allows admins.

The `JwtAuthGuard` ensures that there is a valid JWT and that the user associated with the JWT exists in the database.

### Testing

To test, ensure that the environment is different than the `development` environment. When the end to end tests run, they will delete all users in the database specified in the environment file on start. Currently running `npm run test:e2e` will set `NODE_ENV` to `test` based on `package.json` scripts. This will default to the `test.env` file.

Create `test.env` to have a different database than the `development.env` file. To test Nodemailer include the variable `TEST_EMAIL_TO` which is the email that will receive the password reset email.

#### Example `test.env`

```env
MONGO_URI=mongodb://localhost:27017/user-auth-test
JWT_SECRET=someSecret
EMAIL_SERVICE=Mailgun
EMAIL_USERNAME=email@mailgun.com
EMAIL_PASSWORD=emailSMTPpassword
EMAIL_FROM=from@somedomain.com
TEST_EMAIL_TO=realEmailAddress@somedomain.com
```

### nodemon

To use nodemon there is a small change required. Because the classes file is built from the schema, it is recreated on each launch. Add "src/graphql.classes.ts" in 'nodemon.json' to ignore the changes on that file.

```typescript
{
  "ignore": ["src/**/*.spec.ts", "src/graphql.classes.ts"],
}
```

### GraphQL Playground Examples

```graphql
query loginQuery($loginUser: LoginUserInput!) {
  login(user: $loginUser) {
    token
    user {
      username
      email
    }
  }
}
```

```json
{
  "loginUser": {
    "username": "usersname",
    "password": "passwordOfUser"
  }
}
```

```graphql
query {
  users {
    username
    email
  }
}
```

```graphql
query user {
  user(email: "email@test.com") {
    username
  }
}
```

```graphql
query refreshToken {
  refreshToken(username: "username")
}
```

```graphql
mutation updateUser($updateUser: UpdateUserInput!) {
  updateUser(username: "usernametoUpdate", fieldsToUpdate: $updateUser) {
    username
    email
    updatedAt
    createdAt
  }
}
```

```json
{
  "updateUser": {
    "username": "newUserName",
    "password": "newPassword",
    "email": "newEmail@test.com"
    "enabled": false
  }
}
```

```graphql
mutation CreateUser {
  createUser(
    createUserInput: {
      username: "username"
      email: "user@test.com"
      password: "userspassword"
    }
  ) {
    username
  }
}
```

```graphql
mutation {
  addAdminPermission(username: "someUsername") {
    permissions
  }
}
```

```graphql
mutation {
  removeAdminPermission(username: "someUsername") {
    permissions
  }
}
```

```graphql
query {
  forgotPassword(email: "some-email@email.com")
}
```

```graphql
mutation {
  resetPassword(
    username: "username"
    code: "code-from-the-email"
    password: "password"
  ) {
    username
  }
}
```
