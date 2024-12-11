import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiOAuth2 } from '@nestjs/swagger';
import { AuthResponseDto } from './dto/auth-response.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Google OAuth2 Authentication' })
  @ApiOAuth2(['email', 'profile'])
  @ApiResponse({
    status: 302,
    description: 'Redirects to Google login page',
  })
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Guard redirects to Google
  }

  @ApiOperation({ summary: 'Google OAuth2 Callback' })
  @ApiResponse({
    status: 200,
    description: 'Successfully authenticated with Google',
    type: AuthResponseDto,
  })
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(@Req() req: Request) {
    return this.authService.login(req.user);
  }

  @ApiOperation({ summary: 'GitHub OAuth Authentication' })
  @ApiOAuth2(['user:email'])
  @ApiResponse({
    status: 302,
    description: 'Redirects to GitHub login page',
  })
  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth() {
    // Guard redirects to GitHub
  }

  @ApiOperation({ summary: 'GitHub OAuth Callback' })
  @ApiResponse({
    status: 200,
    description: 'Successfully authenticated with GitHub',
    type: AuthResponseDto,
  })
  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthCallback(@Req() req: Request) {
    return this.authService.login(req.user);
  }
}
