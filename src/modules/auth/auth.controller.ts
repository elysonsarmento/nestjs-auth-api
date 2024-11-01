import {
  Controller,
  Post,
  Get,
  HttpCode,
  Body,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { User } from '../../common/decorators/user.decorator';
import { AuthService } from './auth.service';
import { AuthLoginDto } from './dto/auth-login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshTokenGuard } from './guards/jwt-refresh-token.guard';
import { JwtUserPayload } from '../../common/types/user-payload.type';

const ACCESS_TOKEN_OPTIONS = {
  maxAge: 1000 * 60 * 10,
  httpOnly: true,
};

const REFRESH_TOKEN_OPTIONS = {
  maxAge: 1000 * 60 * 60 * 7,
  httpOnly: true,
};

@Controller('auth')
export class AuthController {
  constructor(private readonly service: AuthService) {}

  @Post('login')
  @HttpCode(200)
  async login(
    @Body() authLoginDto: AuthLoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const { refreshToken, accessToken } = await this.service.login(
        authLoginDto,
      );
      res.cookie('refresh_token', refreshToken, REFRESH_TOKEN_OPTIONS);
      res.cookie('access_token', accessToken, ACCESS_TOKEN_OPTIONS);
    } catch (error) {
      res.status(500).send('Login failed');
    }
  }

  @Get('refresh')
  async refreshAccessToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const cookies = req.cookies ?? req.signedCookies;
      const refreshToken = cookies.refresh_token;
      if (!cookies.access_token) {
        const accessToken = await this.service.updateAccessToken(refreshToken);
        res.cookie('access_token', accessToken, ACCESS_TOKEN_OPTIONS);
      }
    } catch (error) {
      res.status(500).send('Token refresh failed');
    }
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard, JwtRefreshTokenGuard)
  @HttpCode(200)
  async logout(
    @User() user: JwtUserPayload,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      await this.service.logout(user.userId);
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
    } catch (error) {
      res.status(500).send('Logout failed');
    }
  }
}
