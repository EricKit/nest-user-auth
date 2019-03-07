import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginUserInput, User, LoginResult } from '../graphql.classes';
import { UserDocument } from '../users/schemas/user.schema';
import { ConfigService } from '../config/config.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUserByPassword(
    loginAttempt: LoginUserInput,
  ): Promise<LoginResult | undefined> {
    // This will be used for the initial login
    let userToAttempt: UserDocument | undefined;
    if (loginAttempt.email) {
      userToAttempt = await this.usersService.findOneByEmail(
        loginAttempt.email,
      );
    } else if (loginAttempt.username) {
      userToAttempt = await this.usersService.findOneByUsername(
        loginAttempt.username,
      );
    }

    // If the user is not enabled, disable log in - the token wouldn't work anyways
    if (userToAttempt && userToAttempt.enabled === false)
      userToAttempt = undefined;

    return new Promise<LoginResult>(resolve => {
      if (!userToAttempt) {
        resolve(undefined);
        return;
      }
      // Check the supplied password against the hash stored for this email address
      userToAttempt.checkPassword(
        loginAttempt.password,
        (err?: Error, isMatch?: boolean) => {
          if (err) {
            resolve(undefined);
            return;
          }
          if (isMatch) {
            // If there is a successful match, generate a JWT for the user
            const token = this.createJwtPayload(userToAttempt!).token;
            const result: LoginResult = {
              user: userToAttempt!,
              token,
            };
            resolve(result);
          } else {
            resolve(undefined);
          }
        },
      );
    });
  }

  async validateJwtPayload(
    payload: JwtPayload,
  ): Promise<UserDocument | undefined> {
    // This will be used when the user has already logged in and has a JWT
    const user = await this.usersService.findOneByUsername(payload.username);

    // Ensure the user exists and their account isn't disabled
    if (user && user.enabled) {
      return user;
    }

    return undefined;
  }

  async refreshJwt(username: string): Promise<string | undefined> {
    const user = await this.usersService.findOneByUsername(username);
    if (user) return this.createJwtPayload(user).token;
    return undefined;
  }

  createJwtPayload(user: User): { data: JwtPayload; token: string } {
    const expiresIn = this.configService.jwtExpiresIn;
    let expiration: Date | undefined;
    if (expiresIn) {
      expiration = new Date();
      expiration.setSeconds(expiration.getSeconds() + expiresIn);
    }
    const data: JwtPayload = {
      email: user.email,
      username: user.username,
      expiration,
    };

    const jwt = this.jwtService.sign(data);

    return {
      data,
      token: jwt,
    };
  }
}
