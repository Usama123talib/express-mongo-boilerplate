const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const AppError = require('../utils/appError');
const { StatusCodes } = require('../utils/enums/httpStatus.enum');

const authenticate = async (req, res, next) => {
  try {
    let token;
    
    // Check for token in Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token) {
      throw new AppError('Please authenticate to access this resource', StatusCodes.UNAUTHORIZED);
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user still exists
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      throw new AppError('The user belonging to this token no longer exists', StatusCodes.UNAUTHORIZED);
    }
    
    // Check if user is active
    if (user.status !== 'active') {
      throw new AppError('Your account has been deactivated', StatusCodes.UNAUTHORIZED);
    }
    
    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return next(new AppError('Invalid token', StatusCodes.UNAUTHORIZED));
    }
    if (error.name === 'TokenExpiredError') {
      return next(new AppError('Token has expired', StatusCodes.UNAUTHORIZED));
    }
    next(error);
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', StatusCodes.FORBIDDEN)
      );
    }
    next();
  };
};

module.exports = { authenticate, authorize };