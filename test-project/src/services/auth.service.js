const User = require('../models/user.model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const AppError = require('../utils/appError');
const { StatusCodes } = require('../utils/enums/httpStatus.enum');

class AuthService {
  async signup(userData) {
    const { name, email, password } = userData;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new AppError('User already exists with this email', StatusCodes.CONFLICT);
    }
    
    // Create new user
    const user = await User.create({
      name,
      email,
      password
    });
    
    // Generate tokens
    const accessToken = this.generateAccessToken(user._id);
    const refreshToken = this.generateRefreshToken(user._id);
    
    // Remove password from response
    user.password = undefined;
    
    return {
      user,
      accessToken,
      refreshToken
    };
  }

  async login(credentials) {
    const { email, password } = credentials;
    
    // Find user and include password
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      throw new AppError('Invalid email or password', StatusCodes.UNAUTHORIZED);
    }
    
    // Check password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    
    if (!isPasswordCorrect) {
      throw new AppError('Invalid email or password', StatusCodes.UNAUTHORIZED);
    }
    
    // Generate tokens
    const accessToken = this.generateAccessToken(user._id);
    const refreshToken = this.generateRefreshToken(user._id);
    
    // Remove password from response
    user.password = undefined;
    
    return {
      user,
      accessToken,
      refreshToken
    };
  }

  async refreshToken(refreshToken) {
    if (!refreshToken) {
      throw new AppError('Refresh token is required', StatusCodes.BAD_REQUEST);
    }
    
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
      const accessToken = this.generateAccessToken(decoded.id);
      
      return { accessToken };
    } catch (error) {
      throw new AppError('Invalid refresh token', StatusCodes.UNAUTHORIZED);
    }
  }

  generateAccessToken(userId) {
    return jwt.sign(
      { id: userId },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
  }

  generateRefreshToken(userId) {
    return jwt.sign(
      { id: userId },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '30d' }
    );
  }
}

module.exports = new AuthService();