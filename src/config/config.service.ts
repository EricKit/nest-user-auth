import { Injectable } from '@nestjs/common';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as Joi from 'joi';

export interface EnvConfig {
  [key: string]: string;
}

type options =
  | 'MONGO_URI'
  | 'JWT_SECRET'
  | 'JWT_EXPIRES_IN'
  | 'EMAIL_SERVICE'
  | 'EMAIL_USERNAME'
  | 'EMAIL_PASSWORD'
  | 'EMAIL_FROM'
  | 'TEST_EMAIL_TO';

@Injectable()
export class ConfigService {
  private readonly envConfig: EnvConfig;

  constructor(filePath: string) {
    let file: Buffer | undefined;
    try {
      file = fs.readFileSync(filePath);
    } catch (error) {
      file = fs.readFileSync('development.env');
    }

    const config = dotenv.parse(file);
    this.envConfig = this.validateInput(config);
  }

  private validateInput(envConfig: EnvConfig): EnvConfig {
    const envVarsSchema: Joi.ObjectSchema = Joi.object({
      MONGO_URI: Joi.string().required(),
      JWT_SECRET: Joi.string().required(),
      JWT_EXPIRES_IN: Joi.number(),
      EMAIL_ENABLED: Joi.boolean().default(false),
      EMAIL_SERVICE: Joi.string().when('EMAIL_ENABLED', {
        is: true,
        then: Joi.required(),
      }),
      EMAIL_USERNAME: Joi.string().when('EMAIL_ENABLED', {
        is: true,
        then: Joi.required(),
      }),
      EMAIL_PASSWORD: Joi.string().when('EMAIL_ENABLED', {
        is: true,
        then: Joi.required(),
      }),
      EMAIL_FROM: Joi.string().when('EMAIL_ENABLED', {
        is: true,
        then: Joi.required(),
      }),
      TEST_EMAIL_TO: Joi.string(),
    });

    const { error, value: validatedEnvConfig } = Joi.validate(
      envConfig,
      envVarsSchema,
    );
    if (error) {
      throw new Error(
        `Config validation error in your env file: ${error.message}`,
      );
    }
    return validatedEnvConfig;
  }

  get jwtExpiresIn(): number | undefined {
    if (this.envConfig.JWT_EXPIRES_IN) {
      return +this.envConfig.JWT_EXPIRES_IN;
    }
    return undefined;
  }

  get mongoUri(): string {
    return this.envConfig.MONGO_URI;
  }

  get jwtSecret(): string {
    return this.envConfig.JWT_SECRET;
  }

  get emailService(): string | undefined {
    return this.envConfig.EMAIL_SERVICE;
  }

  get emailUsername(): string | undefined {
    return this.envConfig.EMAIL_USERNAME;
  }

  get emailPassword(): string | undefined {
    return this.envConfig.EMAIL_PASSWORD;
  }

  get emailFrom(): string | undefined {
    return this.envConfig.EMAIL_FROM;
  }

  get testEmailTo(): string | undefined {
    return this.envConfig.TEST_EMAIL_TO;
  }

  get emailEnabled(): boolean {
    return Boolean(this.envConfig.EMAIL_ENABLED).valueOf();
  }
}
