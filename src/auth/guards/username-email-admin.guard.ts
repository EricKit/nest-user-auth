import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';
import { GqlExecutionContext } from '@nestjs/graphql';
import { User } from '../../graphql.classes';
import { UsersService } from '../../users/users.service';
import { AuthenticationError } from 'apollo-server-core';

// Check if username in field for query matches authenticated user's username
// or if the user is admin
@Injectable()
export class UsernameEmailAdminGuard implements CanActivate {
  constructor(private usersService: UsersService) {}

  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    let shouldActivate = false;
    if (request.user) {
      const user = <User> request.user;
      if (this.usersService.isAdmin(user.permissions)) return true;
      const args = ctx.getArgs();
      if (args.username && typeof args.username === 'string') {
        shouldActivate =
          args.username.toLowerCase() === user.username.toLowerCase();
      } else if (args.email && typeof args.email === 'string') {
        shouldActivate = args.email.toLowerCase() === user.email.toLowerCase();
      }
    }
    if (!shouldActivate) {
      throw new AuthenticationError('Could not authenticate with token');
    }
    return shouldActivate;
  }
}
