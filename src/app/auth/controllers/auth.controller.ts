import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { Public } from '../../../shared/decorators/public.decorator';
import { LoginDto, SignupDto } from '../dto/auth.dto';
import { CurrentUser } from '../../../shared/decorators/current-user.decorator';
import { UserDocument } from '../../../shared/models/user.model';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @Public()
  async registerUser(@Body() data: SignupDto) {
    return await this.authService.signup(data);
  }

  @Post('login')
  @Public()
  async login(@Body() user: LoginDto) {
    return this.authService.login(user);
  }

  @Get('profile')
  profile(@CurrentUser() user: UserDocument) {
    return this.authService.profile(user);
  }

  @Post('logout')
  async logout(@Req() req: Request) {
    return this.authService.logout(req);
  }
}
