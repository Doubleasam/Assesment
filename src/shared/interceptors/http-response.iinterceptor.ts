import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { Response } from 'express';

@Injectable()
export class HttpResponseInterceptor implements NestInterceptor {
  /**
   * Intercepts and transforms the HTTP response.
   * @param context The execution context.
   * @param next The call handler.
   * @returns An observable containing the transformed response.
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data: unknown | unknown) => {
        const getResponse = context.switchToHttp().getResponse<Response>();
        if (
          getResponse.statusCode === 201 &&
          context.switchToHttp().getRequest().method === 'POST'
        ) {
          getResponse.status(200); // Modify status code to 200 OK
        }
        // Construct the response object
        const response: Record<string, any> = {
          success: true,
          code: getResponse.statusCode,
          message: 'Successful',
          data: data,
        };

        return response;
      }),
      catchError((error) => {
        // Handle error responses here
        return throwError(error);
      }),
    );
  }
}
