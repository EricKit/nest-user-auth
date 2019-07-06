import { Module, forwardRef } from '@nestjs/common';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { AuthResolver } from './auth.resolvers';
import { ConfigService } from '../config/config.service';
import { ConfigModule } from '../config/config.module';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const options: JwtModuleOptions = {
          secret: configService.jwtSecret,
        };
        if (configService.jwtExpiresIn) {
          options.signOptions = {
            expiresIn: configService.jwtExpiresIn,
          };
        }
        return options;
      },
      inject: [ConfigService],
    }),
    forwardRef(() => UsersModule),
    ConfigModule,
  ],
  controllers: [],
  providers: [AuthService, AuthResolver, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
