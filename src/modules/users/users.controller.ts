import {
  Body,
  Controller,
  Get,
  Post,
  UseGuards,
  Patch,
  Res,
  HttpCode,
  Param,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { RequestRecoveryDto } from './dto/request-recovery.dto';
import { FindRecoveryByIdDto } from './dto/find-recovery.dto';
import { RecoveryPasswordDto } from './dto/recovery-password.dto';
import { FindConfirmationByIdDto } from './dto/find-confirmation.dto';
import { User } from '../../common/decorators/user.decorator';
import { JwtUserPayload } from '../../common/types/user-payload.type';

@Controller('users')
export class UsersController {
  constructor(private readonly service: UsersService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createUserDto: CreateUserDto) {
    try {
      return await this.service.create(createUserDto);
    } catch (error) {
      console.log(error);
      throw error;
    }
  }

  @Patch('change-password')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(
    @User() user: JwtUserPayload,
    @Res({ passthrough: true }) res: Response,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    await this.service.changePassword(user.userId, changePasswordDto);
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
  }

  @Post('request-recovery')
  @HttpCode(HttpStatus.OK)
  async requestRecovery(@Body() requestRecoveryDto: RequestRecoveryDto) {
    return await this.service.requestRecovery(requestRecoveryDto.email);
  }

  @Patch('confirm/:confirmationId')
  @HttpCode(HttpStatus.OK)
  async confirm(@Param() findConfirmationByIdDto: FindConfirmationByIdDto) {
    return await this.service.confirm(findConfirmationByIdDto.confirmationId);
  }

  @Get('recovery/:recoveryId')
  @HttpCode(HttpStatus.OK)
  async findRecoveryToken(@Param() findRecoveryByIdDto: FindRecoveryByIdDto) {
    return await this.service.findTokenById(
      findRecoveryByIdDto.recoveryId,
      'RECOVERY',
    );
  }

  @Patch('recovery/:recoveryId')
  @HttpCode(HttpStatus.OK)
  async recovery(
    @Param() findRecoveryByIdDto: FindRecoveryByIdDto,
    @Body() recoveryPasswordDto: RecoveryPasswordDto,
  ) {
    return await this.service.recoveryPassword(
      findRecoveryByIdDto.recoveryId,
      recoveryPasswordDto,
    );
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  me(@User() user: JwtUserPayload) {
    return user;
  }
}
