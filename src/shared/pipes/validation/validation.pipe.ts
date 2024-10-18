import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { validate, ValidationError } from 'class-validator';
import { plainToInstance } from 'class-transformer';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, metadata: ArgumentMetadata) {
    const metatype = metadata.metatype;

    if (!metatype || !this.toValidate(metadata)) {
      return value;
    }

    const object = plainToInstance(metatype, value);
    const errors = await validate(object);
    if (errors.length > 0) {
      throw new HttpException(
        {
          error: 'Validation failed',
          statusCode: HttpStatus.BAD_REQUEST,
          message: this.formatErrors(errors),
        },
        HttpStatus.BAD_REQUEST,
      );
    }
    return value;
  }

  private toValidate(metadata: ArgumentMetadata): boolean {
    const metatype = metadata.metatype;

    const types: any = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }

  private formatErrors(errors: ValidationError[]) {
    const result: any = {};
    errors.forEach((error: ValidationError) => {
      if (error.constraints) {
        result[error.property] = Object.values(error.constraints);
      }
      if (error.children && error.children.length) {
        result[error.property] = this.formatErrors(error.children);
      }
    });
    return result;
  }
}
