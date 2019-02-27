import { Injectable } from '@nestjs/common';
import { Model, connection, mongo } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { UserDocument, UserModel } from './schemas/user.schema';
import { CreateUserInput, UpdateUserInput } from '../graphql.classes';
import { randomBytes } from 'crypto';
import { createTransport, SendMailOptions } from 'nodemailer';
import { ConfigService } from '../config/config.service';
import { MongoError } from 'mongodb';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<UserDocument>,
    private configService: ConfigService,
  ) {}

  isAdmin(permissions: string[]): boolean {
    return permissions.includes('admin');
  }

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

  async update(
    username: string,
    fieldsToUpdate: UpdateUserInput,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);

    if (!user) return undefined;

    if (fieldsToUpdate.username) user.username = fieldsToUpdate.username;
    if (fieldsToUpdate.email) user.email = fieldsToUpdate.email;
    if (fieldsToUpdate.password) user.password = fieldsToUpdate.password;

    // Save will hash the password
    await user.save();
    return user;
  }

  async forgotPassword(email: string): Promise<boolean> {
    const user = await this.findOneByEmail(email);
    if (!user) return false;
    const token = randomBytes(32).toString('hex');

    // One day
    const expiration = new Date(Date().valueOf() + 24 * 60 * 60 * 1000);

    const transporter = createTransport({
      service: this.configService.get('EMAIL_SERVICE'),
      auth: {
        user: this.configService.get('EMAIL_USERNAME'),
        pass: this.configService.get('EMAIL_PASSWORD'),
      },
    });

    const mailOptions: SendMailOptions = {
      from: this.configService.get('EMAIL_FROM'),
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

        user.save().then(() => resolve(true), () => resolve(false));
      });
    });
  }

  async resetPassword(
    username: string,
    code: string,
    password: string,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);
    if (user && user.passwordReset) {
      if (user.passwordReset.token === code) {
        user.password = password;
        user.passwordReset = undefined;
        await user.save();
        return user;
      }
    }
    return undefined;
  }

  async create(createUserInput: CreateUserInput): Promise<UserDocument> {
    const createdUser = new this.userModel(createUserInput);
    createdUser.lowercaseUsername = createdUser.username.toLowerCase();
    createdUser.lowercaseEmail = createdUser.email.toLowerCase();
    let user: UserDocument | undefined;
    try {
      user = await createdUser.save();
    } catch (error) {
      const mongoError = <MongoError> error;
      if (mongoError.code === 11000) {
        if (
          mongoError.message
            .toLowerCase()
            .includes(createUserInput.email.toLowerCase())
        ) {
          throw new Error(
            `e-mail ${createUserInput.email} is already registered`,
          );
        } else if (
          mongoError.message
            .toLowerCase()
            .includes(createUserInput.username.toLowerCase())
        ) {
          throw new Error(
            `Username ${createUserInput.username} is already registered`,
          );
        }
      }
      throw new Error('Re-check input fields');
    }
    return user;
  }

  async findOneByEmail(email: string): Promise<UserDocument | undefined> {
    const user = await this.userModel
      .findOne({ lowercaseEmail: email.toLowerCase() })
      .exec();
    if (user) return user;
    return undefined;
  }

  async findOneByUsername(username: string): Promise<UserDocument | undefined> {
    const user = await this.userModel
      .findOne({ lowercaseUsername: username.toLowerCase() })
      .exec();
    if (user) return user;
    return undefined;
  }

  async getAllUsers(): Promise<UserDocument[]> {
    const users = await this.userModel.find().exec();
    return users;
  }

  async deleteAllUsers(): Promise<void> {
    await this.userModel.deleteMany({});
  }
}
