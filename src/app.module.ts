import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';

import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { join } from 'path';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb://localhost:27017/user-auth', {
      useNewUrlParser: true,
      useCreateIndex: true,
    }),
    GraphQLModule.forRoot({
      typePaths: ['./**/*.graphql'],
      installSubscriptionHandlers: true,
      context: ({ req }: any) => ({ req }),
      definitions: {
        path: join(process.cwd(), 'src/graphql.classes.ts'),
        outputAs: 'class',
      },
    }),
    UsersModule,
    AuthModule,
  ],
})
export class AppModule {}
