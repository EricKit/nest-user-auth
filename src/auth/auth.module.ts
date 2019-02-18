import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JWT_SECRET } from '../../secrets';
import { AuthResolver } from './auth.resolvers';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),
    JwtModule.register({
      secretOrPrivateKey: JWT_SECRET,
      signOptions: {
        expiresIn: 3600,
      },
    }),
    UsersModule,
  ],
  controllers: [],
  providers: [AuthService, AuthResolver, JwtStrategy],
})
export class AuthModule {}
