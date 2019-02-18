import { Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { UserDocument } from './schemas/user.schema';
import { CreateUserInput, UpdateUserInput } from '../graphql.classes';

@Injectable()
export class UsersService {
  constructor(@InjectModel('User') private userModel: Model<UserDocument>) {}

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

  async create(createUserInput: CreateUserInput) {
    const createdUser = new this.userModel(createUserInput);
    return await createdUser.save();
  }

  async findOneByEmail(email: string): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({ email }).exec();
    return user;
  }

  async findOneByUsername(username: string): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({ username }).exec();
    return user;
  }

  async getAllUsers(): Promise<UserDocument[]> {
    const users = await this.userModel.find().exec();
    return users;
  }
}
