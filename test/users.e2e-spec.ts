import { Test, TestingModule } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import { INestApplication } from '@nestjs/common';
import { UsersService } from '../src/users/users.service';
import { disconnect } from 'mongoose';
import { AuthService } from '../src/auth/auth.service';
import { LoginResult } from '../src/graphql.classes';
import { ConfigService } from '../src/config/config.service';

describe('Users (e2e)', () => {
  let app: INestApplication;
  let user1Login: LoginResult;
  let user2Login: LoginResult;
  let adminLogin: LoginResult;
  let usersService: UsersService;
  let configService: ConfigService;
  let authService: AuthService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
      providers: [
        UsersService,
        AuthService,
        ConfigService,
        {
          provide: ConfigService,
          useValue: new ConfigService(`${process.env.NODE_ENV}.env`),
        },
      ],
    }).compile();
    app = moduleFixture.createNestApplication();
    await app.init();

    usersService = moduleFixture.get<UsersService>(UsersService);
    configService = moduleFixture.get<ConfigService>(ConfigService);
    authService = moduleFixture.get<AuthService>(AuthService);

    await usersService.deleteAllUsers();

    await usersService.create({
      username: 'user1',
      email: 'user1@email.com',
      password: 'password1',
    });

    await usersService.create({
      username: 'user2',
      email: 'user2@email.com',
      password: 'password2',
    });

    await usersService.create({
      username: 'admin',
      email: 'admin@email.com',
      password: 'password',
    });

    const adminDocument = await usersService.findOneByUsername('admin');

    adminDocument!.permissions = ['admin'];
    await adminDocument!.save();

    let result = await authService.validateUserByPassword({
      username: 'user1',
      password: 'password1',
    });
    if (result) user1Login = result;

    result = await authService.validateUserByPassword({
      username: 'user2',
      password: 'password2',
    });
    if (result) user2Login = result;

    result = await authService.validateUserByPassword({
      username: 'admin',
      password: 'password',
    });
    if (result) adminLogin = result;
  });

  describe('login', () => {
    it('works', () => {
      const data = {
        query: `{login(user:{username:"user1",password:"password1"}){token user{username}}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.login.user).toMatchObject({
            username: 'user1',
          });
        });
    });

    it('works with different cases on username', () => {
      const data = {
        query: `{login(user:{username:"uSer1",password:"password1"}){token user{username}}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.login.user).toMatchObject({
            username: 'user1',
          });
        });
    });

    it('fails password', () => {
      const data = {
        query: `{login(user:{username:"user1",password:"pAssword1"}){token user{username}}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails username', () => {
      const data = {
        query: `{login(user:{username:"notAUser",password:"password1"}){token user{username}}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body).toHaveProperty('errors');
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });
  });

  describe('get user info', () => {
    it('works with username', () => {
      const data = {
        query: `{user(username:"uSer1"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.user).toMatchObject({
            username: 'user1',
          });
        });
    });

    it('works with email', () => {
      const data = {
        query: `{user(email:"uSer1@email.com"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.user).toMatchObject({
            username: 'user1',
          });
        });
    });

    it('fails with wrong username', () => {
      const data = {
        query: `{user(username:"user10"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails with wrong token', () => {
      const data = {
        query: `{user(username:"user2"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails with wrong no token', () => {
      const data = {
        query: `{user(username:"user10"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails with mispelled token', () => {
      const data = {
        query: `{user(username:"user10"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}a`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });
  });

  describe('get users', () => {
    it('works with admin', () => {
      const data = {
        query: `{users{username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.users).toContainEqual({
            username: 'user1',
          });
          expect(response.body.data.users).toContainEqual({
            username: 'user2',
          });
          expect(response.body.data.users).toContainEqual({
            username: 'admin',
          });
        });
    });

    it('fails with non admin token', () => {
      const data = {
        query: `{users{username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails with no token', () => {
      const data = {
        query: `{users{username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });
  });

  describe('forgot password and reset password', () => {
    let TEST_EMAIL_TO: string;
    let testRequest: request.Test;
    beforeAll(async () => {
      TEST_EMAIL_TO = configService.get(`TEST_EMAIL_TO`);
      if (TEST_EMAIL_TO) {
        await usersService.create({
          username: 'userForgotPassword',
          email: TEST_EMAIL_TO,
          password: 'oldPassword',
        });

        const data = {
          query: `{forgotPassword(email: "${TEST_EMAIL_TO}")}`,
        };
        testRequest = request(app.getHttpServer())
          .post('/graphql')
          .send(data);
      }
    });

    it('responds with 200', () => {
      if (TEST_EMAIL_TO) return testRequest.expect(200);
    });

    it('modifies the user with token and reset password works', async () => {
      if (TEST_EMAIL_TO) {
        let user = await usersService.findOneByEmail(TEST_EMAIL_TO);
        expect(user!.passwordReset).toBeTruthy();
        expect(user!.passwordReset!.token).toBeTruthy();
        expect(user!.passwordReset!.expiration).toBeInstanceOf(Date);

        // Bad token
        let data = {
          query: `mutation {resetPassword(
          username: "userForgotPassword"
          code: "${user!.passwordReset!.token}a"
          password: "newPassword") {
            username
          }
        }`,
        };
        await request(app.getHttpServer())
          .post('/graphql')
          .send(data)
          .expect(200)
          .expect(response => {
            expect(response.body.errors[0].extensions.code).toEqual(
              'BAD_USER_INPUT',
            );
          });

        // Bad username
        data = {
          query: `mutation {resetPassword(
          username: "userForgotPassword2"
          code: "${user!.passwordReset!.token}"
          password: "newPassword") {
            username
          }
        }`,
        };
        await request(app.getHttpServer())
          .post('/graphql')
          .send(data)
          .expect(200)
          .expect(response => {
            expect(response.body.errors[0].extensions.code).toEqual(
              'BAD_USER_INPUT',
            );
          });

        // Correct data being passed
        data = {
          query: `mutation {resetPassword(
          username: "userForgotPassword"
          code: "${user!.passwordReset!.token}"
          password: "newPassword") {
            username
          }
        }`,
        };
        await request(app.getHttpServer())
          .post('/graphql')
          .send(data)
          .expect(200)
          .expect(response => {
            expect(response.body.data.resetPassword).toMatchObject({
              username: `userForgotPassword`,
            });
          });

        // Verify that the new password works
        expect(
          await authService.validateUserByPassword({
            username: `userForgotPassword`,
            password: `newPassword`,
          }),
        ).toBeTruthy();

        // Ensure the token was removed from the user
        user = await usersService.findOneByEmail(TEST_EMAIL_TO);
        expect(user!.passwordReset).toBeFalsy();

        // Make sure the old password does not work
        expect(
          await authService.validateUserByPassword({
            username: `userForgotPassword`,
            password: `oldPassword`,
          }),
        ).toBeFalsy();
      }
    });
  });

  describe('create user', () => {
    it('works', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "user3",
            email:"user3@email.com",
            password:"password"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.createUser).toMatchObject({
            username: 'user3',
          });
        });
    });

    it('fails for duplicate username', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "usEr2",
            email:"user4@email.com",
            password:"password"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'BAD_USER_INPUT',
          );
        });
    });

    it('fails for duplicate email', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "user4",
            email:"user2@emAil.com",
            password:"password"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'BAD_USER_INPUT',
          );
        });
    });

    it('fails for no username', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            email:"user5@email.com",
            password:"password"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(400)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'GRAPHQL_VALIDATION_FAILED',
          );
        });
    });

    it('fails for no password', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "user5",
            email:"user5@email.com"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(400)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'GRAPHQL_VALIDATION_FAILED',
          );
        });
    });

    it('fails for no email', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "user5",
            password:"password"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(400)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'GRAPHQL_VALIDATION_FAILED',
          );
        });
    });

    it('fails for bad email, no @', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "user5",
            password: "password",
            email: "email.com"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'BAD_USER_INPUT',
          );
        });
    });
  });

  describe('update user', () => {
    it('works with all fields', async () => {
      await usersService.create({
        username: 'userToUpdate1',
        email: 'userToUpdate1@email.com',
        password: 'password',
      });

      const result = await authService.validateUserByPassword({
        username: 'userToUpdate1',
        password: 'password',
      });
      const token = result!.token;

      const data = {
        query: `mutation {
          updateUser(
            username: "userToUpdate1",
            fieldsToUpdate: {
            username: "newUsername1",
            email: "newUser1@email.com",
            password: "newPassword"
          }) {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${token!}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            username: 'newUsername1',
            email: 'newUser1@email.com',
          });
        });

      const login = await authService.validateUserByPassword({
        username: 'newUsername1',
        password: 'newPassword',
      });
      expect(login).toBeTruthy();
    });

    it('updates other fields with changed username already in use', async () => {
      await usersService.create({
        username: 'userToUpdate2',
        email: 'userToUpdate2@email.com',
        password: 'password',
      });

      const result = await authService.validateUserByPassword({
        username: 'userToUpdate2',
        password: 'password',
      });
      const token = result!.token;

      const data = {
        query: `mutation {
          updateUser(username: "userToUpdate2",
            fieldsToUpdate: {
            username: "user1",
            email:"newUser2@email.com",
            password:"newPassword"
          }) {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            username: 'userToUpdate2',
            email: 'newUser2@email.com',
          });
        });

      expect(
        await authService.validateUserByPassword({
          username: 'uSerToUpdate2',
          password: 'newPassword',
        }),
      ).toBeTruthy();
    });

    it('updates other fields with email already in use', async () => {
      await usersService.create({
        username: 'userToUpdate3',
        email: 'userToUpdate3@email.com',
        password: 'password',
      });

      const result = await authService.validateUserByPassword({
        username: 'userToUpdate3',
        password: 'password',
      });
      const token = result!.token;

      const data = {
        query: `mutation {
          updateUser(username: "userToUpdate3",
            fieldsToUpdate: {
            username: "newUsername3",
            email:"user1@email.com",
            password:"newPassword"
          }) {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            username: 'newUsername3',
            email: 'userToUpdate3@email.com',
          });
        });

      expect(
        await authService.validateUserByPassword({
          username: 'newUsername3',
          password: 'newPassword',
        }),
      ).toBeTruthy();
    });

    it('updates other fields with invalid email', async () => {
      await usersService.create({
        username: 'userToUpdate4',
        email: 'userToUpdate4@email.com',
        password: 'password',
      });

      const result = await authService.validateUserByPassword({
        username: 'userToUpdate4',
        password: 'password',
      });
      const token = result!.token;

      const data = {
        query: `mutation {
          updateUser(username: "userToUpdate4",
            fieldsToUpdate: {
            username: "newUsername5",
            email:"invalidEmail",
            password:"newPassword"
          }) {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            username: 'newUsername5',
            email: 'userToUpdate4@email.com',
          });
        });

      expect(
        await authService.validateUserByPassword({
          username: 'newUsername5',
          password: 'newPassword',
        }),
      ).toBeTruthy();
    });

    it('updates with no fields returns the user', async () => {
      const data = {
        query: `mutation {
          updateUser(username: "user1",
            fieldsToUpdate: {})
            {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            username: 'user1',
            email: 'user1@email.com',
          });
        });

      expect(
        await authService.validateUserByPassword({
          username: 'user1',
          password: 'password1',
        }),
      ).toBeTruthy();
    });

    it('fails to update with wrong username', async () => {
      const data = {
        query: `mutation {
          updateUser(username: "user2",
            fieldsToUpdate: {email: "newEmail11@email.com"})
            {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails to update with username that does not exist', async () => {
      const data = {
        query: `mutation {
          updateUser(username: "doesNotExist",
            fieldsToUpdate: {email: "newEmail11@email.com"})
            {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });
  });

  afterAll(() => {
    disconnect();
  });
});
