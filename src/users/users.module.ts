import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { PassportModule } from '@nestjs/passport';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema } from './schemas/user.schema';
import { UserResolver } from './users.resolvers';
import { DateScalar } from '../scalars/date.scalar';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'User', schema: UserSchema }]),
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),
  ],
  exports: [UsersService],
  controllers: [],
  providers: [UsersService, UserResolver, DateScalar],
})
export class UsersModule {}
