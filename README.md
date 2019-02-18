# nest-user-auth

## Purpose

This is a boiler plate project to start with user authentication. I plan on adding more capability. Feel free to throw spears at it or recommend updates. Standard disclaimer: In no way has this been vetted by security experts.

## Technologies

The project is built using MongoDB with Mongoose for the database. The project is built around NestJS and @nestjs/graphql. Passport is used for authentication and the strategy is Passport-JWT.

## Model Management

The goal is to have one truth point for the models. That is the `*.types.graphql` files. They contain the GraphQL schema. Then `@nestjs/graphql` creates the `graphql.classes.ts` file. These classes are used as the base class for the Mongoose Schema and in place of DTOs. Of note, I'd like to use the IMutation and IQuery methods in the resolvers, I'm just not sure how that'd work.

## Usage

Add a secrets.ts file at the base of the project that contains `export const JWT_SECRET = 'ChangeThisValue';`

Add a user via the graphQL playground. Then update that user to have `admin` in the permissions array on the user's Document. I use MongoDB Compass to do that. That user can now add admin or remove admin permission to other users.

Users can change their username, password, or email via a mutation. Changing their username will make their token unusable (it won't authenticate when the user presenting the token is checked against the token's data). So in essence it'll log them out. May or may not be the desired behavior. If using on a front end, I'd make it obvious that you can change your username and it'll log them out. For this reason, \_id should be used for many-to-many relationships.

### Authentication

Add the token to your headers `{"Authorization": "Bearer eyJhbGc..."}`

Admin must be set manually as a string in permissions for the first user (add `admin` to the permissions array). That person can then add admin to other users via a mutation. Permissions is an array of strings so that you can add other permissions and create guards such as `can-modify-users-with-prime-number-id`.

Users can modify or view their own data. Admins can do anything (in current guards). The UserEmailGuard compares the user's email or username with the same field in a query. If any query or mutation in the resolver has doAnythingWithUser(username: string) or doAnythingWithUser(email: string) and that email / username matches the user which is requesting the action, it will be approved. Username and email are unique, and the user has already been verified via JWT.

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
