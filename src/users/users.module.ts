import { Module, forwardRef } from '@nestjs/common';
import { UsersService } from './users.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema } from './schemas/user.schema';
import { UserResolver } from './users.resolvers';
import { DateScalar } from '../scalars/date.scalar';
import { ConfigModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'User', schema: UserSchema }]),
    UsersModule,
    ConfigModule,
    forwardRef(() => AuthModule),
  ],
  exports: [UsersService],
  controllers: [],
  providers: [UsersService, UserResolver, DateScalar],
})
export class UsersModule {}
