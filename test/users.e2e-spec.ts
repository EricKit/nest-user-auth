import { Test, TestingModule } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import { INestApplication } from '@nestjs/common';
import { UsersService } from '../src/users/users.service';
import { disconnect } from 'mongoose';
import { AuthService } from '../src/auth/auth.service';
import { LoginResult } from '../src/graphql.classes';
import { ConfigService } from '../src/config/config.service';
import { JwtService } from '@nestjs/jwt';
import { UsersModule } from '../src/users/users.module';
import { AuthModule } from '../src/auth/auth.module';
import { ConfigModule } from '../src/config/config.module';

describe('Users (e2e)', () => {
  let app: INestApplication;
  let user1Login: LoginResult;
  let user2Login: LoginResult;
  let adminLogin: LoginResult;
  let disabledUserLogin: LoginResult;
  let disabledAdminLogin: LoginResult;
  let usersService: UsersService;
  let configService: ConfigService;
  let authService: AuthService;
  let jwtService: JwtService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, UsersModule, AuthModule, ConfigModule],
      providers: [],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    usersService = moduleFixture.get<UsersService>(UsersService);
    configService = moduleFixture.get<ConfigService>(ConfigService);
    authService = moduleFixture.get<AuthService>(AuthService);
    jwtService = moduleFixture.get<JwtService>(JwtService);

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
      username: 'disabledUser',
      email: 'disabledUser@email.com',
      password: 'password',
    });

    await usersService.create({
      username: 'admin',
      email: 'admin@email.com',
      password: 'password',
    });

    await usersService.create({
      username: 'disabledAdmin',
      email: 'disabledAdmin@email.com',
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

    result = await authService.validateUserByPassword({
      username: 'disabledUser',
      password: 'password',
    });
    if (result) disabledUserLogin = result;

    result = await authService.validateUserByPassword({
      username: 'disabledAdmin',
      password: 'password',
    });
    if (result) disabledAdminLogin = result;

    await usersService.update('disabledUser', { enabled: false });
    await usersService.update('disabledAdmin', { enabled: false });
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

    it('fails for disabled user', () => {
      const data = {
        query: `{login(user:{username:"disabledUser",password:"password"}){token user{username}}}`,
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

    it('fails for disabled admin', () => {
      const data = {
        query: `{login(user:{username:"disabledAdmin",password:"password"}){token user{username}}}`,
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

  describe('refresh token', () => {
    it('works', async () => {
      const data = {
        query: `{refreshToken}`,
      };

      await new Promise(resolve => {
        setTimeout(resolve, 1000);
      });
      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user1Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data).toHaveProperty('refreshToken');
          const newToken = response.body.data.refreshToken;
          const verified = jwtService.verify(newToken);
          expect(verified).toBeTruthy();
          const newtokenIssued = new Date(verified.iat * 1000);
          const oldTokenIssued = new Date(
            jwtService.verify(user1Login.token).iat * 1000,
          );
          expect(
            newtokenIssued.valueOf() - oldTokenIssued.valueOf(),
          ).toBeGreaterThan(0);
        });
    });

    it('fails for disabled user', () => {
      const data = {
        query: `{refreshToken}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledUserLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails for disabled admin', () => {
      const data = {
        query: `{refreshToken}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledAdminLogin.token}`)
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
        query: `{refreshToken}`,
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
        query: `{refreshToken}`,
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

    it('works for admin', () => {
      const data = {
        query: `{user(username:"uSer1"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token}`)
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

    it('fails for disabled user', () => {
      const data = {
        query: `{user(username:"disabledUser"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledUserLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails for disabled admin', () => {
      const data = {
        query: `{user(username:"disabledAdmin"){username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledAdminLogin.token}`)
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

    it('fails with no token', () => {
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
          expect(response.body.data.users).toContainEqual({
            username: 'disabledUser',
          });
          expect(response.body.data.users).toContainEqual({
            username: 'disabledAdmin',
          });
        });
    });

    it('fails for disabled admin', () => {
      const data = {
        query: `{users{username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledAdminLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
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
    let testEmailTo: string | undefined;
    let runEmailTests = false;
    let testRequest: request.Test;
    beforeAll(async () => {
      testEmailTo = configService.testEmailTo;
      if (testEmailTo && configService.emailEnabled) {
        runEmailTests = true;
        await usersService.create({
          username: 'userForgotPassword',
          email: testEmailTo,
          password: 'oldPassword',
        });

        const data = {
          query: `{forgotPassword(email: "${testEmailTo}")}`,
        };
        testRequest = request(app.getHttpServer())
          .post('/graphql')
          .send(data);
      }
    });

    it('responds with 200', () => {
      if (runEmailTests) return testRequest.expect(200);
    });

    it('modifies the user with token and reset password works', async () => {
      if (runEmailTests) {
        let user = await usersService.findOneByEmail(testEmailTo!);
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
        user = await usersService.findOneByEmail(testEmailTo!);
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
            password: {
              oldPassword: "password",
              newPassword: "newPassword",
            }
            enabled: true
          }) {username, email, enabled}}`,
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
            enabled: true,
          });
        });

      const login = await authService.validateUserByPassword({
        username: 'newUsername1',
        password: 'newPassword',
      });
      expect(login).toBeTruthy();
    });

    it('disables a user', async () => {
      await usersService.create({
        username: 'userToDisable',
        email: 'userToDisable@email.com',
        password: 'password',
      });

      const result = await authService.validateUserByPassword({
        username: 'userToDisable',
        password: 'password',
      });
      const token = result!.token;

      const data = {
        query: `mutation {
          updateUser(
            username: "userToDisable",
            fieldsToUpdate: {
            enabled: false
          }) {enabled}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${token!}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            enabled: false,
          });
        });

      const login = await authService.validateUserByPassword({
        username: 'userToDisable',
        password: 'password',
      });
      expect(login).not.toBeTruthy();
    });

    it('works with for admin', async () => {
      await usersService.create({
        username: 'userToUpdateByAdmin',
        email: 'userToUpdatebyAdmin@email.com',
        password: 'password',
      });

      const data = {
        query: `mutation {
          updateUser(
            username: "userToUpdateByAdmin",
            fieldsToUpdate: {
            username: "newUsernameByAdmin",
            email: "newUserByAdmin@email.com",
          }) {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token!}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            username: 'newUsernameByAdmin',
            email: 'newUserByAdmin@email.com',
          });
        });
    });

    it("fails with admin changing another user's password", async () => {
      await usersService.create({
        username: 'userToUpdateByAdmin2',
        email: 'userToUpdatebyAdmin2@email.com',
        password: 'password',
      });

      const data = {
        query: `mutation {
          updateUser(
            username: "userToUpdateByAdmin2",
            fieldsToUpdate: {
            username: "newUsernameByAdmin2",
            email: "newUserByAdmin2@email.com",
            password: {
              oldPassword: "password",
              newPassword: "newPassword",
            }
          }) {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token!}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
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
            password: {
              oldPassword: "password",
              newPassword: "newPassword",
            }
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
            password: {
              oldPassword: "password",
              newPassword: "newPassword",
            }
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
            password: {
              oldPassword: "password",
              newPassword: "newPassword",
            }
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

    it(`update other fields with bad old password - also verifies updates requesting user's info
    with no username set`, async () => {
      await usersService.create({
        username: 'userToUpdate55',
        email: 'userToUpdate55@email.com',
        password: 'password',
      });

      const result = await authService.validateUserByPassword({
        username: 'userToUpdate55',
        password: 'password',
      });
      const token = result!.token;

      const data = {
        query: `mutation {
          updateUser(
            fieldsToUpdate: {
            username: "newUsername55",
            email: "newUser55@email.com",
            password: {
              oldPassword: "notthepassword",
              newPassword: "newPassword",
            }
            enabled: true
          }) {username, email, enabled}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${token!}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.data.updateUser).toMatchObject({
            username: 'newUsername55',
            email: 'newUser55@email.com',
            enabled: true,
          });
        });

      let login = await authService.validateUserByPassword({
        username: 'newUsername55',
        password: 'newPassword',
      });
      expect(login).toBeFalsy();

      login = await authService.validateUserByPassword({
        username: 'newUsername55',
        password: 'password',
      });
      expect(login).toBeTruthy();
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

    it('fails to update with no token', async () => {
      const data = {
        query: `mutation {
          updateUser(username: "user1",
            fieldsToUpdate: {email: "newEmail11@email.com"})
            {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails to update with invalid token', async () => {
      const data = {
        query: `mutation {
          updateUser(username: "user1",
            fieldsToUpdate: {email: "newEmail11@email.com"})
            {username, email}}`,
      };

      await request(app.getHttpServer())
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

    it('fails for disabled user', async () => {
      const data = {
        query: `mutation {
          updateUser(username: "disabledUser",
            fieldsToUpdate: {email: "newEmail11@email.com"})
            {username, email}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledUserLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });
  });

  describe('admin permissions', () => {
    it('adds and removes the permission', async () => {
      await usersService.create({
        username: 'userToBeAdmin',
        email: 'userToBeAdmin@email.com',
        password: 'password',
      });

      let data = {
        query: `mutation {addAdminPermission(username: "userToBeAdmin") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(
            response.body.data.addAdminPermission.permissions,
          ).toContainEqual(`admin`);
        });

      // Make sure admin isn't added twice
      data = {
        query: `mutation {addAdminPermission(username: "userToBeAdmin") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(
            response.body.data.addAdminPermission.permissions,
          ).toContainEqual(`admin`);
          expect(
            response.body.data.addAdminPermission.permissions,
          ).toHaveLength(1);
        });

      // Can remove admin
      data = {
        query: `mutation {removeAdminPermission(username: "userToBeAdmin") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(
            response.body.data.removeAdminPermission.permissions,
          ).not.toContainEqual(`admin`);
          expect(
            response.body.data.removeAdminPermission.permissions,
          ).toHaveLength(0);
        });

      // Make sure there are no issues when removing an adming where it doesn't exist
      data = {
        query: `mutation {removeAdminPermission(username: "userToBeAdmin") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${adminLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(
            response.body.data.removeAdminPermission.permissions,
          ).not.toContainEqual(`admin`);
          expect(
            response.body.data.removeAdminPermission.permissions,
          ).toHaveLength(0);
        });
    });

    it('fails for user', async () => {
      // Own user's token
      const data = {
        query: `mutation {addAdminPermission(username: "user1") {permissions}}`,
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

    it('fails for user trying to update another', async () => {
      // Another user's token (non-admin)
      const data = {
        query: `mutation {addAdminPermission(username: "user1") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${user2Login.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails for disabled user', async () => {
      const data = {
        query: `mutation {addAdminPermission(username: "disabledUser") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledUserLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails for disabled admin', async () => {
      const data = {
        query: `mutation {addAdminPermission(username: "user1") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${disabledAdminLogin.token}`)
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails for no token', async () => {
      const data = {
        query: `mutation {addAdminPermission(username: "user1") {permissions}}`,
      };

      await request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body.errors[0].extensions.code).toEqual(
            'UNAUTHENTICATED',
          );
        });
    });

    it('fails for invalid token', async () => {
      const data = {
        query: `mutation {addAdminPermission(username: "user1") {permissions}}`,
      };

      await request(app.getHttpServer())
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

  afterAll(() => {
    disconnect();
  });
});
