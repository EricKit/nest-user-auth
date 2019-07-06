import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { User } from '../../graphql.classes';
import { UsersService } from '../../users/users.service';
import { AuthenticationError } from 'apollo-server-core';
import { Reflector } from '@nestjs/core';

// Check if username in field for query matches authenticated user's username
// or if the user is admin
@Injectable()
export class UsernameEmailAdminGuard implements CanActivate {
  constructor(
    private usersService: UsersService,
    private readonly reflector: Reflector,
  ) {}

  // Returns an array of all the properties of an object seperated by a .
  getPropertiesArray(object: any): string[] {
    let result: string[] = [];
    Object.entries(object).forEach(([key, value]) => {
      const field = key;
      if (typeof value === 'object' && value !== null) {
        const objectProperties = this.getPropertiesArray(value).map(
          prop => `${field}.${prop}`,
        );
        result = result.concat(objectProperties);
      } else {
        result.push(field);
      }
    });
    return result;
  }

  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    let shouldActivate = false;
    if (request.user) {
      const user = <User> request.user;
      const args = ctx.getArgs();
      if (args.username && typeof args.username === 'string') {
        shouldActivate =
          args.username.toLowerCase() === user.username.toLowerCase();
      } else if (args.email && typeof args.email === 'string') {
        shouldActivate = args.email.toLowerCase() === user.email.toLowerCase();
      } else if (!args.username && !args.email) {
        shouldActivate = true;
      }

      if (
        shouldActivate === false &&
        this.usersService.isAdmin(user.permissions)
      ) {
        const adminAllowedArgs = this.reflector.get<string[]>(
          'adminAllowedArgs',
          context.getHandler(),
        );

        shouldActivate = true;

        if (adminAllowedArgs) {
          const argFields = this.getPropertiesArray(args);
          argFields.forEach(field => {
            if (!adminAllowedArgs.includes(field)) {
              throw new AuthenticationError(
                `Admin is not allowed to modify ${field}`,
              );
            }
          });
        }
      }
    }
    if (!shouldActivate) {
      throw new AuthenticationError('Could not authenticate with token');
    }
    return shouldActivate;
  }
}
