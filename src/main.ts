import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app/app.module';
import { VersioningType } from '@nestjs/common';
import * as compression from 'compression';
import helmet from 'helmet';
import { ValidationPipe } from './shared/pipes/validation/validation.pipe';
import { HttpExceptionFilter } from './shared/exceptions/http.exception';
import { HttpResponseInterceptor } from './shared/interceptors/http-response.iinterceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Set necessary headers for security
  app.use(helmet());

  // Enable cors
  app.enableCors();

  // compression for responses
  app.use(compression());

  // Api versioning
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  app.useGlobalInterceptors(new HttpResponseInterceptor());

  // validation pipe
  app.useGlobalPipes(new ValidationPipe());
  // useContainer(app.select(AppModule), { fallbackOnErrors: true });

  // exception filters
  const { httpAdapter } = app.get(HttpAdapterHost);
  app.useGlobalFilters(new HttpExceptionFilter(httpAdapter));

  const port = parseInt(String(process.env.PORT)) || 3000;
  console.log(port);

  await app.listen(port, '0.0.0.0');
}
bootstrap();
