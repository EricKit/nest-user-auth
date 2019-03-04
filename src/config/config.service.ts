import { Injectable } from '@nestjs/common';
import * as dotenv from 'dotenv';
import * as fs from 'fs';

@Injectable()
export class ConfigService {
  private readonly envConfig: { [key: string]: string };

  constructor(filePath: string) {
    let file: Buffer | undefined;
    try {
      file = fs.readFileSync(filePath);
    } catch (error) {
      file = fs.readFileSync('dev.env');
    }
    this.envConfig = dotenv.parse(file);
  }

  get(key: string): string {
    return this.envConfig[key];
  }

  set(key: string, value: string) {
    this.envConfig[key] = value;
  }
}
