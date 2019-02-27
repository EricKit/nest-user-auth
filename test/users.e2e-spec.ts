import { Test, TestingModule } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import { INestApplication } from '@nestjs/common';
import { UsersService } from '../src/users/users.service';
import { disconnect } from 'mongoose';

describe('Users (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
      providers: [UsersService],
    }).compile();
    app = moduleFixture.createNestApplication();
    await app.init();

    const usersService = moduleFixture.get<UsersService>(UsersService);
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
          expect(response.body.data).toHaveProperty('login');
          expect(response.body.data.login).toHaveProperty('token');
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
          expect(response.body.data).toHaveProperty('login');
          expect(response.body.data.login).toHaveProperty('token');
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
          expect(response.body).toHaveProperty('errors');
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

  describe('createUser', () => {
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
            username: "usEr3",
            email:"user4@email.com",
            password:"password"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body).toHaveProperty('errors');
        });
    });

    it('fails for duplicate email', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "user4",
            email:"user3@emAil.com",
            password:"password"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(200)
        .expect(response => {
          expect(response.body).toHaveProperty('errors');
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
        .expect(400);
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
        .expect(400);
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
        .expect(400);
    });

    /* Not Implemented
    it('fails for bad email no dot', () => {
      const data = {
        query: `mutation {
          createUser(createUserInput: {
            username: "user5",
            password: "password",
            email: "user@email"
          }) {username}}`,
      };
      return request(app.getHttpServer())
        .post('/graphql')
        .send(data)
        .expect(400);
    });

    it('fails for bad email no @', () => {
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
        .expect(400);
    });
    */
  });

  afterAll(() => {
    disconnect();
  });
});
