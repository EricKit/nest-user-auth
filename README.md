# nest-user-auth

## Next task

Let me know what features you'd like to see. The ability to reset a user's password via email was added.

## Purpose

This is a boiler plate project to start with user authentication. Adding other GraphQL models to this project will be easy following the same structure. User auth has always been the hardest and most common thing to implement, so that is what is implemented in this project. Feel free to throw spears at this project or recommend updates. Standard disclaimer: In no way has this been vetted by security experts.

## Technologies

The project is built using MongoDB with Mongoose for the database. The project is built around NestJS and @nestjs/graphql. Passport is used for authentication and the strategy is Passport-JWT. Nodemailer is used for email password reset.

## Model Management

The goal is to have one truth point for the models. That is the `*.types.graphql` files. They contain the GraphQL schema. Then `@nestjs/graphql` creates the `graphql.classes.ts` file. These classes are used as the base class for the Mongoose Schema and in place of DTOs. Of note, I'd like to use the IMutation and IQuery methods in the resolvers, I'm just not sure how that'd work.

Username as the primary field to identify a user in a request. Initially username or email were excepted, but for simplicity the schema moved to only username. Both are in the JWT data. Email could be used too. Both are unique.

The databse stores a unique lowercase value for both username and email. This is to lookup the user with. The normal cased version is used for everything but lookup and only the database is aware lowercase values exists. GraphQL is not.

## Usage

Ensure a MongoDB server is running locally.

To use email, register with any dedicated SMTP server. Gmail doesn't let you change your from address and has other limiations. Mailgun is recommended. With mailgun use their SMTP service, not the API.

Add a secrets.ts file at the base of the project that contains.

```typescript
// JWT Auth Secret
export const JWT_SECRET = 'someSecret';

// Email secrets
export const EMAIL_SERVICE = 'Mailgun';
export const EMAIL_USERNAME = 'mailgun username';
export const EMAIL_PASSWORD = 'mailgun password for SMTP username';
export const EMAIL_FROM = 'from@somedomain.com';
```

Start the server

`npm install`
`npm run start`

Add a user via the graphql playground or your frontend.

`http://localhost:3000/graphql`

Then update that user's Document to have the string `admin` in the permissions array. MongoDB Compass is a great tool to do that and view your schema. That user can now add admin or remove admin permission to other users.

Users can change their username, password, or email via a mutation. Changing their username will make their token unusable (it won't authenticate when the user presenting the token's username is checked against the token's username). This may or may not be the desired behavior. If using on a front end, make it obvious that you can change your username and it'll log the user out (front end must get a new token via logging in).

Because you can change both unique properties username and email, \_id should be used for many-to-many relationships.

### Authentication

Add the token to your headers `{"Authorization": "Bearer eyj2aGc..."}`

Admin must be set manually as a string in permissions for the first user (add `admin` to the permissions array). That person can then add admin to other users via a mutation. Permissions is an array of strings so that you can add other permissions and create guards such as `can-modify-users-with-prime-number-id`.

Users can modify or view their own data. Admins can do anything in the current guards. The UserEmailGuard compares the user's email or username with the same field in a query. If any query or mutation in the resolver has doAnythingWithUser(username: string) or doAnythingWithUser(email: string) and that email / username matches the user which is requesting the action, it will be approved. Username and email are unique, and the user has already been verified via JWT.

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
  getUsers {
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
