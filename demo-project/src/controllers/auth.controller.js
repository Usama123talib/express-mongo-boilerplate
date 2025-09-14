const authService = require('../services/auth.service');
const { StatusCodes } = require('../utils/enums/httpStatus.enum');

class AuthController {
  async signup(req, res) {
    const result = await authService.signup(req.body);
    
    res.status(StatusCodes.CREATED).json({
      success: true,
      message: 'User registered successfully',
      data: result
    });
  }

  async login(req, res) {
    const result = await authService.login(req.body);
    
    res.status(StatusCodes.OK).json({
      success: true,
      message: 'Login successful',
      data: result
    });
  }

  async refreshToken(req, res) {
    const { refreshToken } = req.body;
    const result = await authService.refreshToken(refreshToken);
    
    res.status(StatusCodes.OK).json({
      success: true,
      message: 'Token refreshed successfully',
      data: result
    });
  }

  async logout(req, res) {
    // In a real application, you might want to blacklist the token
    res.status(StatusCodes.OK).json({
      success: true,
      message: 'Logged out successfully'
    });
  }
}

module.exports = new AuthController();