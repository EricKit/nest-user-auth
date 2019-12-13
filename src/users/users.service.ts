import { Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { UserDocument, UserModel } from './schemas/user.schema';
import { CreateUserInput, UpdateUserInput } from '../graphql.classes';
import { randomBytes } from 'crypto';
import { createTransport, SendMailOptions } from 'nodemailer';
import { ConfigService } from '../config/config.service';
import { MongoError } from 'mongodb';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<UserDocument>,
    private configService: ConfigService,
    private authService: AuthService,
  ) {}

  /**
   * Returns if the user has 'admin' set on the permissions array
   *
   * @param {string[]} permissions permissions property on a User
   * @returns {boolean}
   * @memberof UsersService
   */
  isAdmin(permissions: string[]): boolean {
    return permissions.includes('admin');
  }

  /**
   * Adds any permission string to the user's permissions array property. Checks if that value exists
   * before adding it.
   *
   * @param {string} permission The permission to add to the user
   * @param {string} username The user's username
   * @returns {(Promise<UserDocument | undefined>)} The user Document with the updated permission. Undefined if the
   * user does not exist
   * @memberof UsersService
   */
  async addPermission(
    permission: string,
    username: string,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);
    if (!user) return undefined;
    if (user.permissions.includes(permission)) return user;
    user.permissions.push(permission);
    await user.save();
    return user;
  }

  /**
   * Removes any permission string from the user's permissions array property.
   *
   * @param {string} permission The permission to remove from the user
   * @param {string} username The username of the user to remove the permission from
   * @returns {(Promise<UserDocument | undefined>)} Returns undefined if the user does not exist
   * @memberof UsersService
   */
  async removePermission(
    permission: string,
    username: string,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);
    if (!user) return undefined;
    user.permissions = user.permissions.filter(
      userPermission => userPermission !== permission,
    );
    await user.save();
    return user;
  }

  /**
   * Updates a user in the database. If any value is invalid, it will still update the other
   * fields of the user.
   *
   * @param {string} username of the user to update
   * @param {UpdateUserInput} fieldsToUpdate The user can update their username, email, password, or enabled. If
   * the username is updated, the user's token will no longer work. If the user disables their account, only an admin
   * can reenable it
   * @returns {(Promise<UserDocument | undefined>)} Returns undefined if the user cannot be found
   * @memberof UsersService
   */
  async update(
    username: string,
    fieldsToUpdate: UpdateUserInput,
  ): Promise<UserDocument | undefined> {
    if (fieldsToUpdate.username) {
      const duplicateUser = await this.findOneByUsername(
        fieldsToUpdate.username,
      );
      if (duplicateUser) fieldsToUpdate.username = undefined;
    }

    if (fieldsToUpdate.email) {
      const duplicateUser = await this.findOneByEmail(fieldsToUpdate.email);
      const emailValid = UserModel.validateEmail(fieldsToUpdate.email);
      if (duplicateUser || !emailValid) fieldsToUpdate.email = undefined;
    }

    const fields: any = {};

    if (fieldsToUpdate.password) {
      if (
        await this.authService.validateUserByPassword({
          username,
          password: fieldsToUpdate.password.oldPassword,
        })
      ) {
        fields.password = fieldsToUpdate.password.newPassword;
      }
    }

    // Remove undefined keys for update
    for (const key in fieldsToUpdate) {
      if (typeof fieldsToUpdate[key] !== 'undefined' && key !== 'password') {
        fields[key] = fieldsToUpdate[key];
      }
    }

    let user: UserDocument | undefined | null = null;

    if (Object.entries(fieldsToUpdate).length > 0) {
      user = await this.userModel.findOneAndUpdate(
        { lowercaseUsername: username.toLowerCase() },
        fields,
        { new: true, runValidators: true },
      );
    } else {
      user = await this.findOneByUsername(username);
    }

    if (!user) return undefined;

    return user;
  }

  /**
   * Send an email with a password reset code and sets the reset token and expiration on the user.
   * EMAIL_ENABLED must be true for this to run.
   *
   * @param {string} email address associated with an account to reset
   * @returns {Promise<boolean>} if an email was sent or not
   * @memberof UsersService
   */
  async forgotPassword(email: string): Promise<boolean> {
    if (!this.configService.emailEnabled) return false;

    const user = await this.findOneByEmail(email);
    if (!user) return false;
    if (!user.enabled) return false;

    const token = randomBytes(32).toString('hex');

    // One day for expiration of reset token
    const expiration = new Date(Date().valueOf() + 24 * 60 * 60 * 1000);

    const transporter = createTransport({
      service: this.configService.emailService,
      auth: {
        user: this.configService.emailUsername,
        pass: this.configService.emailPassword,
      },
    });

    const mailOptions: SendMailOptions = {
      from: this.configService.emailFrom,
      to: email,
      subject: `Reset Password`,
      text: `${user.username},
      Replace this with a website that can pass the token:
      ${token}`,
    };

    return new Promise(resolve => {
      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          resolve(false);
          return;
        }

        user.passwordReset = {
          token,
          expiration,
        };

        user.save().then(
          () => resolve(true),
          () => resolve(false),
        );
      });
    });
  }

  /**
   * Resets a password after the user forgot their password and requested a reset
   *
   * @param {string} username
   * @param {string} code the token set when the password reset email was sent out
   * @param {string} password the new password the user wants
   * @returns {(Promise<UserDocument | undefined>)} Returns undefined if the code or the username is wrong
   * @memberof UsersService
   */
  async resetPassword(
    username: string,
    code: string,
    password: string,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);
    if (user && user.passwordReset && user.enabled !== false) {
      if (user.passwordReset.token === code) {
        user.password = password;
        user.passwordReset = undefined;
        await user.save();
        return user;
      }
    }
    return undefined;
  }

  /**
   * Creates a user
   *
   * @param {CreateUserInput} createUserInput username, email, and password. Username and email must be
   * unique, will throw an email with a description if either are duplicates
   * @returns {Promise<UserDocument>} or throws an error
   * @memberof UsersService
   */
  async create(createUserInput: CreateUserInput): Promise<UserDocument> {
    const createdUser = new this.userModel(createUserInput);

    let user: UserDocument | undefined;
    try {
      user = await createdUser.save();
    } catch (error) {
      throw this.evaluateMongoError(error, createUserInput);
    }
    return user;
  }

  /**
   * Returns a user by their unique email address or undefined
   *
   * @param {string} email address of user, not case sensitive
   * @returns {(Promise<UserDocument | undefined>)}
   * @memberof UsersService
   */
  async findOneByEmail(email: string): Promise<UserDocument | undefined> {
    const user = await this.userModel
      .findOne({ lowercaseEmail: email.toLowerCase() })
      .exec();
    if (user) return user;
    return undefined;
  }

  /**
   * Returns a user by their unique username or undefined
   *
   * @param {string} username of user, not case sensitive
   * @returns {(Promise<UserDocument | undefined>)}
   * @memberof UsersService
   */
  async findOneByUsername(username: string): Promise<UserDocument | undefined> {
    const user = await this.userModel
      .findOne({ lowercaseUsername: username.toLowerCase() })
      .exec();
    if (user) return user;
    return undefined;
  }

  /**
   * Gets all the users that are registered
   *
   * @returns {Promise<UserDocument[]>}
   * @memberof UsersService
   */
  async getAllUsers(): Promise<UserDocument[]> {
    const users = await this.userModel.find().exec();
    return users;
  }

  /**
   * Deletes all the users in the database, used for testing
   *
   * @returns {Promise<void>}
   * @memberof UsersService
   */
  async deleteAllUsers(): Promise<void> {
    await this.userModel.deleteMany({});
  }

  /**
   * Reads a mongo database error and attempts to provide a better error message. If
   * it is unable to produce a better error message, returns the original error message.
   *
   * @private
   * @param {MongoError} error
   * @param {CreateUserInput} createUserInput
   * @returns {Error}
   * @memberof UsersService
   */
  private evaluateMongoError(
    error: MongoError,
    createUserInput: CreateUserInput,
  ): Error {
    if (error.code === 11000) {
      if (
        error.message
          .toLowerCase()
          .includes(createUserInput.email.toLowerCase())
      ) {
        throw new Error(
          `e-mail ${createUserInput.email} is already registered`,
        );
      } else if (
        error.message
          .toLowerCase()
          .includes(createUserInput.username.toLowerCase())
      ) {
        throw new Error(
          `Username ${createUserInput.username} is already registered`,
        );
      }
    }
    throw new Error(error.message);
  }
}
