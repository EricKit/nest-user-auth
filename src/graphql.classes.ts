/* tslint:disable */
export abstract class CreateUserInput {
    username: string;
    email: string;
    password: string;
}

export abstract class LoginUserInput {
    username?: string;
    email?: string;
    password: string;
}

export abstract class UpdateUserInput {
    username?: string;
    email?: string;
    password?: string;
}

export abstract class LoginResult {
    user: User;
    token: string;
}

export abstract class IMutation {
    abstract createUser(createUserInput?: CreateUserInput): User | Promise<User>;

    abstract updateUser(username: string, fieldsToUpdate: UpdateUserInput): User | Promise<User>;

    abstract addAdminPermission(username: string): User | Promise<User>;

    abstract removeAdminPermission(username: string): User | Promise<User>;

    abstract resetPassword(username: string, code: string, password: string): User | Promise<User>;
}

export abstract class IQuery {
    abstract login(user: LoginUserInput): LoginResult | Promise<LoginResult>;

    abstract users(): User[] | Promise<User[]>;

    abstract user(username?: string, email?: string): User | Promise<User>;

    abstract forgotPassword(email?: string): boolean | Promise<boolean>;

    abstract temp__(): boolean | Promise<boolean>;
}

export abstract class User {
    username: string;
    email: string;
    permissions: string[];
    createdAt: Date;
    updatedAt: Date;
}

export type Date = any;
