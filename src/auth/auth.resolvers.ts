import { Resolver, Args, Query, Context } from '@nestjs/graphql';
import { LoginUserInput, LoginResult } from '../graphql.classes';
import { AuthService } from './auth.service';
import { AuthenticationError } from 'apollo-server-core';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UseGuards } from '@nestjs/common';
import { UserDocument } from '../users/schemas/user.schema';

@Resolver('Auth')
export class AuthResolver {
  constructor(private authService: AuthService) {}

  @Query('login')
  async login(@Args('user') user: LoginUserInput): Promise<LoginResult> {
    const result = await this.authService.validateUserByPassword(user);
    if (result) return result;
    throw new AuthenticationError(
      'Could not log-in with the provided credentials',
    );
  }

  // There is no username guard here because if the person has the token, they can be any user
  @Query('refreshToken')
  @UseGuards(JwtAuthGuard)
  async refreshToken(@Context('req') request: any): Promise<string> {
    const user: UserDocument = request.user;
    if (!user)
      throw new AuthenticationError(
        'Could not log-in with the provided credentials',
      );
    const result = await this.authService.createJwt(user);
    if (result) return result.token;
    throw new AuthenticationError(
      'Could not log-in with the provided credentials',
    );
  }
}
