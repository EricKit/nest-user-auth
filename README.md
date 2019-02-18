# nest-user-auth

## Purpose

This is a boiler plate project to start with user authentication. I plan on adding more capability. Feel free to throw spears at it or recommend updates.

## Technologies

The project is built using MongoDB with Mongoose for the database. The project is built around NestJS and @nestjs/graphql. Passport is used for authentication and the strategy is Passport-JWT.

## Model Management

The goal is to have one truth point for the models. That is the `*.types.graphql` files. They contain the GraphQL schema. Then `@nestjs/graphql` creates the `graphql.classes.ts` file. These classes are used as the base class for the Mongoose Schema and in place of DTOs. Of note, I'd like to use the IMutation and IQuery methods in the resolvers, I'm just not sure how that'd work.

## Usage

Add a secrets.ts file at the base of the project that contains `export const JWT_SECRET = 'ChangeThisValue';`

### GraphQL Playground Examples:

```
query loginQuery($loginUser: LoginUserInput!) {
  login(
    user: $loginUser
  ) {
    token
    user {
      username
      email
    }
  }
}
```
```
{
  "loginUser": {
    "username": "usersname", 
    "password": "passwordOfUser"
  }
}
```
```
query {
  getUsers{
    username
    email
  }
}
```
```
query user{
  user(email: "email@test.com") {
    username
  }
}
```
```
mutation updateUser($updateUser: UpdateUserInput!) {
  updateUser(username: "usernametoUpdate", fieldsToUpdate: $updateUser) {
    username
    email
    updatedAt
    createdAt
  }
}
```
```
{
  "updateUser": {
    "username": "newUserName", 
    "password": "newPassword",
    "email": "newEmail@test.com"
  }
}
```
```
mutation CreateUser {
  createUser(createUserInput: {
    username: "username",
    email:"user@test.com",
    password:"userspassword"
  }) {
    username
  }
}
```

### Authentication

Add the token to your headers `{"Authorization": "Bearer eyJhbGc..."}`

Admin must be set manually as a string in permissions for a user, I'll add that soon.
