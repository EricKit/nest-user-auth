import { Resolver, Args, Query } from '@nestjs/graphql';
import { LoginUserInput, LoginResult } from '../graphql.classes';
import { AuthService } from './auth.service';
import { AuthenticationError } from 'apollo-server-core';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UseGuards } from '@nestjs/common';
import { UsernameEmailGuard } from './guards/username-email.guard';

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
  @UseGuards(JwtAuthGuard, UsernameEmailGuard)
  async refreshToken(@Args('username') username: string): Promise<string> {
    const result = await this.authService.refreshJwt(username);
    if (result) return result;
    throw new AuthenticationError(
      'Could not log-in with the provided credentials',
    );
  }
}
