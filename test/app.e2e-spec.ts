import { Test, TestingModule } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import { INestApplication } from '@nestjs/common';
import { UsersService } from '../src/users/users.service';
import { getModelToken, MongooseModule } from '@nestjs/mongoose';
import { UserModel } from '../src/users/schemas/user.schema';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
      providers: [
        UsersService,
        {
          provide: getModelToken('User'),
          useValue: UserModel,
        },
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('login works', () => {
    const data = {
      query: `{login(user:{username:"eric",password:"password"}){token user{username}}}`,
    };
    return request(app.getHttpServer())
      .post('/graphql')
      .send(data)
      .expect(200)
      .expect(response => {
        expect(response.body.data.login).toHaveProperty('token');
        expect(response.body.data.login.user).toMatchObject({
          username: 'eric',
        });
      });
  });
});
