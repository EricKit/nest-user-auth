import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginUserInput, User, LoginResult } from '../graphql.classes';
import { UserDocument } from '../users/schemas/user.schema';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
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

  async validateUserByJwt(
    payload: JwtPayload,
  ): Promise<UserDocument | undefined> {
    // This will be used when the user has already logged in and has a JWT
    const user = await this.usersService.findOneByUsername(payload.username);

    if (user) {
      return user;
    }

    return undefined;
  }

  createJwtPayload(user: User) {
    const data: JwtPayload = {
      email: user.email,
      username: user.username,
    };

    const jwt = this.jwtService.sign(data);

    return {
      expiresIn: 3600,
      token: jwt,
    };
  }
}
