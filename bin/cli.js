#!/usr/bin/env node

const { program } = require("commander");
const inquirer = require("inquirer");
const fs = require("fs-extra");
const path = require("path");
const chalk = require("chalk");

// Template files content
const templates = {
  "package.json": (projectName) => `{
  "name": "${projectName}",
  "version": "1.0.0",
  "description": "Express MongoDB application with service layer architecture",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js",
    "test": "jest",
    "lint": "eslint ."
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.0.0",
    "dotenv": "^16.0.3",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.7.0",
    "joi": "^17.9.2",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "compression": "^1.7.4",
    "morgan": "^1.10.0",
    "express-async-errors": "^3.1.1"
  },
  "devDependencies": {
    "nodemon": "^2.0.20",
    "eslint": "^8.35.0",
    "jest": "^29.4.3",
    "supertest": "^6.3.3"
  }
}`,

  ".env.example": `# Server Configuration
PORT=3000
NODE_ENV=development

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/your_database_name

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_change_this
JWT_EXPIRE=30d

# API Configuration
API_PREFIX=/api/v1
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Pagination
DEFAULT_PAGE=1
DEFAULT_LIMIT=10
MAX_LIMIT=100`,

  ".gitignore": `node_modules/
.env
.env.local
.DS_Store
*.log
dist/
build/
coverage/
.idea/
.vscode/
*.swp
*.swo
.nyc_output/`,

  "src/server.js": `require('dotenv').config();
const mongoose = require('mongoose');
const app = require('./app');

const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB connected successfully');
  
  // Start server after DB connection
  app.listen(PORT, () => {
    console.log(\`🚀 Server running in \${process.env.NODE_ENV} mode on port \${PORT}\`);
  });
})
.catch((err) => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  process.exit(1);
});

// Handle SIGTERM
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  mongoose.connection.close(() => {
    console.log('💔 MongoDB connection closed.');
    process.exit(0);
  });
});`,

  "src/app.js": `const express = require('express');
require('express-async-errors');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

// Import routes
const authRoutes = require('./routes/auth.route');
const userRoutes = require('./routes/user.route');

// Import middleware
const errorHandler = require('./middleware/errorHandler');
const notFound = require('./middleware/notFound');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
app.use(compression());

// Logging middleware
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV
  });
});

// API routes
const apiPrefix = process.env.API_PREFIX || '/api/v1';
app.use(\`\${apiPrefix}/auth\`, authRoutes);
app.use(\`\${apiPrefix}/users\`, userRoutes);

// 404 handler
app.use(notFound);

// Global error handler (must be last)
app.use(errorHandler);

module.exports = app;`,

  "src/routes/auth.route.js": `const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { validateSignup, validateLogin } = require('../validators/auth.validator');

// @route   POST /api/v1/auth/signup
// @desc    Register a new user
// @access  Public
router.post('/signup', validateSignup, authController.signup);

// @route   POST /api/v1/auth/login
// @desc    Login user
// @access  Public
router.post('/login', validateLogin, authController.login);

// @route   POST /api/v1/auth/refresh
// @desc    Refresh access token
// @access  Public
router.post('/refresh', authController.refreshToken);

// @route   POST /api/v1/auth/logout
// @desc    Logout user
// @access  Public
router.post('/logout', authController.logout);

module.exports = router;`,

  "src/routes/user.route.js": `const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');
const { authenticate, authorize } = require('../middleware/auth');
const { validateUpdateUser, validateUserId } = require('../validators/user.validator');

// @route   GET /api/v1/users
// @desc    Get all users with pagination
// @access  Public
router.get('/', userController.getAllUsers);

// @route   GET /api/v1/users/:id
// @desc    Get user by ID
// @access  Public
router.get('/:id', validateUserId, userController.getUserById);

// @route   GET /api/v1/users/profile/me
// @desc    Get current user profile
// @access  Private
router.get('/profile/me', authenticate, userController.getMyProfile);

// @route   PUT /api/v1/users/:id
// @desc    Update user
// @access  Private
router.put('/:id', authenticate, validateUserId, validateUpdateUser, userController.updateUser);

// @route   DELETE /api/v1/users/:id
// @desc    Delete user
// @access  Private/Admin
router.delete('/:id', authenticate, authorize('admin'), validateUserId, userController.deleteUser);

module.exports = router;`,

  "src/controllers/auth.controller.js": `const authService = require('../services/auth.service');
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

module.exports = new AuthController();`,

  "src/controllers/user.controller.js": `const userService = require('../services/user.service');
const { StatusCodes } = require('../utils/enums/httpStatus.enum');

class UserController {
  async getAllUsers(req, res) {
    const { page, limit, sort, filter } = req.query;
    const users = await userService.getAllUsers({ page, limit, sort, filter });
    
    res.status(StatusCodes.OK).json({
      success: true,
      data: users
    });
  }

  async getUserById(req, res) {
    const user = await userService.getUserById(req.params.id);
    
    res.status(StatusCodes.OK).json({
      success: true,
      data: user
    });
  }

  async getMyProfile(req, res) {
    const user = await userService.getUserById(req.user.id);
    
    res.status(StatusCodes.OK).json({
      success: true,
      data: user
    });
  }

  async updateUser(req, res) {
    const user = await userService.updateUser(req.params.id, req.body, req.user);
    
    res.status(StatusCodes.OK).json({
      success: true,
      message: 'User updated successfully',
      data: user
    });
  }

  async deleteUser(req, res) {
    await userService.deleteUser(req.params.id);
    
    res.status(StatusCodes.NO_CONTENT).json({
      success: true,
      message: 'User deleted successfully'
    });
  }
}

module.exports = new UserController();`,

  "src/services/auth.service.js": `const User = require('../models/user.model');
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

module.exports = new AuthService();`,

  "src/services/user.service.js": `const User = require('../models/user.model');
const AppError = require('../utils/appError');
const { StatusCodes } = require('../utils/enums/httpStatus.enum');

class UserService {
  async getAllUsers({ page = 1, limit = 10, sort = '-createdAt', filter = {} }) {
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;
    
    // Parse filter if it's a string
    let filterObj = {};
    if (typeof filter === 'string') {
      try {
        filterObj = JSON.parse(filter);
      } catch (e) {
        filterObj = {};
      }
    }
    
    const users = await User.find(filterObj)
      .select('-password')
      .sort(sort)
      .skip(skip)
      .limit(limitNum);
    
    const total = await User.countDocuments(filterObj);
    
    return {
      users,
      pagination: {
        total,
        page: pageNum,
        pages: Math.ceil(total / limitNum),
        limit: limitNum
      }
    };
  }

  async getUserById(userId) {
    const user = await User.findById(userId).select('-password');
    
    if (!user) {
      throw new AppError('User not found', StatusCodes.NOT_FOUND);
    }
    
    return user;
  }

  async updateUser(userId, updateData, currentUser) {
    // Check if user is updating their own profile or is admin
    if (currentUser.id !== userId && currentUser.role !== 'admin') {
      throw new AppError('You can only update your own profile', StatusCodes.FORBIDDEN);
    }
    
    // Prevent updating sensitive fields
    delete updateData.password;
    delete updateData.role;
    
    const user = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!user) {
      throw new AppError('User not found', StatusCodes.NOT_FOUND);
    }
    
    return user;
  }

  async deleteUser(userId) {
    const user = await User.findByIdAndDelete(userId);
    
    if (!user) {
      throw new AppError('User not found', StatusCodes.NOT_FOUND);
    }
    
    return user;
  }
}

module.exports = new UserService();`,

  "src/models/user.model.js": `const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { UserRoles, UserStatus } = require('../utils/enums/user.enum');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters'],
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^\\w+([\\.-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,3})+$/,
      'Please provide a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: Object.values(UserRoles),
    default: UserRoles.USER
  },
  status: {
    type: String,
    enum: Object.values(UserStatus),
    default: UserStatus.ACTIVE
  },
  profilePicture: {
    type: String,
    default: null
  },
  phoneNumber: {
    type: String,
    match: [/^[0-9]{10,15}$/, 'Please provide a valid phone number']
  },
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    zipCode: String
  },
  lastLogin: {
    type: Date,
    default: null
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ status: 1 });
userSchema.index({ role: 1 });

// Virtual for full address
userSchema.virtual('fullAddress').get(function() {
  if (!this.address || !this.address.street) return null;
  const { street, city, state, country, zipCode } = this.address;
  return \`\${street}, \${city}, \${state} \${zipCode}, \${country}\`.trim();
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Update lastLogin on login
userSchema.methods.updateLastLogin = function() {
  this.lastLogin = new Date();
  return this.save();
};

module.exports = mongoose.model('User', userSchema);`,

  "src/validators/auth.validator.js": `const Joi = require('joi');
const validate = require('../middleware/validate');

const signupSchema = Joi.object({
  name: Joi.string()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.empty': 'Name is required',
      'string.min': 'Name must be at least 2 characters',
      'string.max': 'Name cannot exceed 50 characters'
    }),
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.empty': 'Email is required',
      'string.email': 'Please provide a valid email'
    }),
  password: Joi.string()
    .min(6)
    .required()
    .messages({
      'string.empty': 'Password is required',
      'string.min': 'Password must be at least 6 characters'
    }),
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Passwords do not match',
      'string.empty': 'Please confirm your password'
    })
});

const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.empty': 'Email is required',
      'string.email': 'Please provide a valid email'
    }),
  password: Joi.string()
    .required()
    .messages({
      'string.empty': 'Password is required'
    })
});

module.exports = {
  validateSignup: validate(signupSchema),
  validateLogin: validate(loginSchema)
};`,

  "src/validators/user.validator.js": `const Joi = require('joi');
const validate = require('../middleware/validate');

const updateUserSchema = Joi.object({
  name: Joi.string()
    .min(2)
    .max(50)
    .optional(),
  phoneNumber: Joi.string()
    .pattern(/^[0-9]{10,15}$/)
    .optional()
    .messages({
      'string.pattern.base': 'Please provide a valid phone number'
    }),
  address: Joi.object({
    street: Joi.string().optional(),
    city: Joi.string().optional(),
    state: Joi.string().optional(),
    country: Joi.string().optional(),
    zipCode: Joi.string().optional()
  }).optional()
});

const userIdSchema = Joi.object({
  id: Joi.string()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .required()
    .messages({
      'string.pattern.base': 'Invalid user ID format'
    })
});

module.exports = {
  validateUpdateUser: validate(updateUserSchema),
  validateUserId: validate(userIdSchema, 'params')
};`,

  "src/middleware/validate.js": `const AppError = require('../utils/appError');
const { StatusCodes } = require('../utils/enums/httpStatus.enum');

const validate = (schema, property = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], {
      abortEarly: false,
      stripUnknown: true
    });
    
    if (error) {
      const errorMessage = error.details
        .map(detail => detail.message)
        .join(', ');
      
      return next(new AppError(errorMessage, StatusCodes.BAD_REQUEST));
    }
    
    // Replace request property with validated value
    req[property] = value;
    next();
  };
};

module.exports = validate;`,

  "src/middleware/auth.js": `const jwt = require('jsonwebtoken');
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

module.exports = { authenticate, authorize };`,

  "src/middleware/errorHandler.js": `const AppError = require('../utils/appError');
const { StatusCodes } = require('../utils/enums/httpStatus.enum');

const handleCastErrorDB = (err) => {
  const message = \`Invalid \${err.path}: \${err.value}\`;
  return new AppError(message, StatusCodes.BAD_REQUEST);
};

const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg.match(/(["'])(\\\\?.)*?\\1/)[0];
  const message = \`Duplicate field value: \${value}. Please use another value!\`;
  return new AppError(message, StatusCodes.BAD_REQUEST);
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = \`Invalid input data. \${errors.join('. ')}\`;
  return new AppError(message, StatusCodes.BAD_REQUEST);
};

const handleJWTError = () =>
  new AppError('Invalid token. Please log in again!', StatusCodes.UNAUTHORIZED);

const handleJWTExpiredError = () =>
  new AppError('Your token has expired! Please log in again.', StatusCodes.UNAUTHORIZED);

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    success: false,
    error: err,
    message: err.message,
    stack: err.stack
  });
};

const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message
    });
  } else {
    // Programming or other unknown error: don't leak error details
    console.error('ERROR 💥', err);
    
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: 'Something went wrong!'
    });
  }
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

    sendErrorProd(error, res);
  }
};`,

  "src/middleware/notFound.js": `const { StatusCodes } = require('../utils/enums/httpStatus.enum');

module.exports = (req, res, next) => {
  res.status(StatusCodes.NOT_FOUND).json({
    success: false,
    message: \`Cannot find \${req.originalUrl} on this server!\`
  });
};`,

  "src/utils/appError.js": `class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    
    this.statusCode = statusCode;
    this.status = \`\${statusCode}\`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;`,

  "src/utils/enums/httpStatus.enum.js": `const StatusCodes = {
  // Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  
  // Redirection
  MOVED_PERMANENTLY: 301,
  FOUND: 302,
  NOT_MODIFIED: 304,
  
  // Client Errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  
  // Server Errors
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
};

module.exports = { StatusCodes };`,

  "src/utils/enums/user.enum.js": `const UserRoles = {
  ADMIN: 'admin',
  USER: 'user',
  MODERATOR: 'moderator'
};

const UserStatus = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  BANNED: 'banned',
  SUSPENDED: 'suspended'
};

module.exports = {
  UserRoles,
  UserStatus
};`,

  "src/utils/enums/auth.enum.js": `const AuthProviders = {
  LOCAL: 'local',
  GOOGLE: 'google',
  FACEBOOK: 'facebook',
  GITHUB: 'github'
};

const TokenTypes = {
  ACCESS: 'access',
  REFRESH: 'refresh',
  RESET_PASSWORD: 'resetPassword',
  VERIFY_EMAIL: 'verifyEmail'
};

module.exports = {
  AuthProviders,
  TokenTypes
};`,

  "README.md": `# Express MongoDB Boilerplate

A production-ready boilerplate with service layer architecture for building RESTful APIs with Express.js and MongoDB.

## 🏗️ Architecture

This boilerplate follows a clean architecture pattern with proper separation of concerns:

- **Routes** - Define API endpoints and route parameters
- **Controllers** - Handle HTTP requests and responses
- **Services** - Contain all business logic and database interactions
- **Validators** - Joi schemas for request validation
- **Models** - Mongoose schemas and data models
- **Middleware** - Custom middleware for auth, error handling, etc.
- **Utils/Enums** - Utility functions and enum constants

## Features

- **Service Layer Architecture** - Clean separation of concerns
- **Joi Validation** - Robust request validation
- **JWT Authentication** - Access and refresh tokens
- **MongoDB with Mongoose** - ODM for MongoDB
- **Error Handling** - Centralized error management
- **Security** - Helmet, CORS, rate limiting
- **Pagination** - Built-in pagination support
- **Environment Config** - dotenv for configuration
- **Logging** - Morgan for HTTP request logging
- **Development Tools** - Nodemon, ESLint, Jest

## Quick Start

1. Install dependencies:
\`\`\`bash
npm install
\`\`\`

2. Set up environment variables:
\`\`\`bash
cp .env.example .env
\`\`\`

3. Update the .env file with your configuration

4. Start MongoDB locally or use MongoDB Atlas

5. Run the development server:
\`\`\`bash
npm run dev
\`\`\`

## Project Structure

\`\`\`
src/
├── controllers/       # Request/Response handling
│   ├── auth.controller.js
│   └── user.controller.js
├── services/         # Business logic
│   ├── auth.service.js
│   └── user.service.js
├── routes/           # API endpoints
│   ├── auth.route.js
│   └── user.route.js
├── models/           # Database schemas
│   └── user.model.js
├── validators/       # Request validation
│   ├── auth.validator.js
│   └── user.validator.js
├── middleware/       # Custom middleware
│   ├── auth.js
│   ├── errorHandler.js
│   ├── notFound.js
│   └── validate.js
├── utils/            # Utilities
│   ├── appError.js
│   └── enums/       # Enum constants
│       ├── auth.enum.js
│       ├── httpStatus.enum.js
│       └── user.enum.js
├── app.js           # Express app setup
└── server.js        # Server entry point
\`\`\`

## API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Body |
|--------|----------|-------------|------|
| POST | \`/api/v1/auth/signup\` | Register new user | \`{ name, email, password, confirmPassword }\` |
| POST | \`/api/v1/auth/login\` | Login user | \`{ email, password }\` |
| POST | \`/api/v1/auth/refresh\` | Refresh access token | \`{ refreshToken }\` |
| POST | \`/api/v1/auth/logout\` | Logout user | - |

### User Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | \`/api/v1/users\` | Get all users (paginated) | No |
| GET | \`/api/v1/users/:id\` | Get user by ID | No |
| GET | \`/api/v1/users/profile/me\` | Get current user profile | Yes |
| PUT | \`/api/v1/users/:id\` | Update user | Yes |
| DELETE | \`/api/v1/users/:id\` | Delete user | Yes (Admin) |

## License

MIT

---

**Created with ❤️ using [Express MongoDB Boilerplate Generator](https://github.com/Usama123talib/express-mongo-boilerplate) by Usama Talib**`,

  ".eslintrc.json": `{
  "env": {
    "node": true,
    "es2021": true,
    "jest": true
  },
  "extends": "eslint:recommended",
  "parserOptions": {
    "ecmaVersion": 12
  },
  "rules": {
    "indent": ["error", 2],
    "linebreak-style": ["error", "unix"],
    "quotes": ["error", "single"],
    "semi": ["error", "always"],
    "no-unused-vars": ["error", { "argsIgnorePattern": "next" }],
    "no-console": "off",
    "comma-dangle": ["error", "never"],
    "prefer-const": "error",
    "arrow-spacing": "error"
  }
}`,

  ".prettierrc": `{
  "semi": true,
  "trailingComma": "none",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "bracketSpacing": true,
  "arrowParens": "always",
  "endOfLine": "lf"
}`,

  "jest.config.js": `module.exports = {
  testEnvironment: 'node',
  coveragePathIgnorePatterns: ['/node_modules/'],
  testMatch: ['**/__tests__/**/*.js', '**/?(*.)+(spec|test).js'],
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/server.js',
    '!src/app.js'
  ],
  coverageDirectory: 'coverage',
  testTimeout: 10000
};`,

  "__tests__/setup.js": `const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

let mongoServer;

// Connect to in-memory database before all tests
beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
});

// Clear all test data after every test
afterEach(async () => {
  const collections = mongoose.connection.collections;
  
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany();
  }
});

// Disconnect and stop server after all tests
afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});`,

  "__tests__/auth.test.js": `const request = require('supertest');
const app = require('../src/app');
const User = require('../src/models/user.model');

describe('Auth Endpoints', () => {
  describe('POST /api/v1/auth/signup', () => {
    test('should register a new user', async () => {
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        confirmPassword: 'password123'
      };

      const res = await request(app)
        .post('/api/v1/auth/signup')
        .send(userData);

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('accessToken');
      expect(res.body.data).toHaveProperty('refreshToken');
      expect(res.body.data.user.email).toBe(userData.email);
    });

    test('should not register user with existing email', async () => {
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      };

      // Create user first
      await User.create(userData);

      const res = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          ...userData,
          confirmPassword: 'password123'
        });

      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/v1/auth/login', () => {
    test('should login with valid credentials', async () => {
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      };

      // Create user
      await User.create(userData);

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('accessToken');
      expect(res.body.data).toHaveProperty('refreshToken');
    });

    test('should not login with invalid credentials', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });
});`,

  "docker-compose.yml": `version: '3.8'

services:
  app:
    build: .
    container_name: express-api
    restart: unless-stopped
    env_file: .env
    ports:
      - "\${PORT}:3000"
    depends_on:
      - mongodb
    networks:
      - app-network
    volumes:
      - .:/app
      - /app/node_modules

  mongodb:
    image: mongo:6
    container_name: mongodb
    restart: unless-stopped
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=admin123
    ports:
      - "27017:27017"
    volumes:
      - mongodb-data:/data/db
    networks:
      - app-network

networks:
  app-network:
    driver: bridge

volumes:
  mongodb-data:`,

  Dockerfile: `FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \\
    adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Start application
CMD ["node", "src/server.js"]`,
};

// Create project structure
async function createProject(projectName, options) {
  const projectPath = path.join(process.cwd(), projectName);

  try {
    // Check if directory exists
    if (await fs.pathExists(projectPath)) {
      console.log(chalk.red(`❌ Directory ${projectName} already exists!`));
      process.exit(1);
    }

    console.log(chalk.blue("📦 Creating project structure..."));

    // Create project directory
    await fs.ensureDir(projectPath);

    // Create subdirectories with new structure
    const directories = [
      "src",
      "src/controllers",
      "src/services",
      "src/routes",
      "src/models",
      "src/validators",
      "src/middleware",
      "src/utils",
      "src/utils/enums",
      "__tests__",
    ];

    for (const dir of directories) {
      await fs.ensureDir(path.join(projectPath, dir));
    }

    // Create files
    console.log(chalk.blue("📝 Creating files..."));

    for (const [filename, content] of Object.entries(templates)) {
      const filePath = path.join(projectPath, filename);
      const fileContent =
        typeof content === "function" ? content(projectName) : content;
      await fs.writeFile(filePath, fileContent);
    }

    // Create .env file from .env.example
    await fs.copy(
      path.join(projectPath, ".env.example"),
      path.join(projectPath, ".env")
    );

    console.log(chalk.green("✅ Project created successfully!"));
    console.log(chalk.cyan("\n📋 Project structure:"));
    console.log(
      chalk.white(`
    ${projectName}/
    ├── src/
    │   ├── controllers/    # Handle requests/responses
    │   ├── services/       # Business logic & DB operations
    │   ├── routes/         # API endpoints
    │   ├── models/         # Mongoose schemas
    │   ├── validators/     # Joi validation schemas
    │   ├── middleware/     # Custom middleware
    │   ├── utils/          # Utilities
    │   │   └── enums/      # Enum constants
    │   ├── app.js          # Express app
    │   └── server.js       # Entry point
    ├── __tests__/          # Test files
    ├── .env                # Environment variables
    ├── package.json        # Dependencies
    └── README.md           # Documentation
    `)
    );

    console.log(chalk.yellow("\n📌 Next steps:"));
    console.log(chalk.white(`   cd ${projectName}`));
    console.log(chalk.white("   npm install"));
    console.log(chalk.white("   # Update .env with your MongoDB URI"));
    console.log(chalk.white("   npm run dev"));

    if (options.git) {
      console.log(chalk.blue("\n🔧 Initializing git repository..."));
      const { execSync } = require("child_process");
      execSync("git init", { cwd: projectPath });
      console.log(chalk.green("✅ Git repository initialized"));
    }
  } catch (error) {
    console.error(chalk.red("Error creating project:"), error);
    process.exit(1);
  }
}

// CLI Program
program
  .version("1.0.0")
  .description("Create a new Express MongoDB boilerplate project");

program
  .command("create <project-name>")
  .description("Create a new project")
  .option("-g, --git", "Initialize git repository")
  .option("-i, --install", "Install dependencies automatically")
  .action(async (projectName, options) => {
    await createProject(projectName, options);

    if (options.install) {
      console.log(chalk.blue("\n📦 Installing dependencies..."));
      const { execSync } = require("child_process");
      execSync("npm install", {
        cwd: path.join(process.cwd(), projectName),
        stdio: "inherit",
      });
      console.log(chalk.green("✅ Dependencies installed"));
    }
  });

// Interactive mode
program
  .command("init")
  .description("Initialize a new project interactively")
  .action(async () => {
    const answers = await inquirer.prompt([
      {
        type: "input",
        name: "projectName",
        message: "Project name:",
        validate: (input) => {
          if (!input) return "Project name is required";
          if (!/^[a-z0-9-_]+$/.test(input)) {
            return "Project name can only contain lowercase letters, numbers, hyphens, and underscores";
          }
          return true;
        },
      },
      {
        type: "confirm",
        name: "git",
        message: "Initialize git repository?",
        default: true,
      },
      {
        type: "confirm",
        name: "install",
        message: "Install dependencies now?",
        default: true,
      },
    ]);

    await createProject(answers.projectName, answers);

    if (answers.install) {
      console.log(chalk.blue("\n📦 Installing dependencies..."));
      const { execSync } = require("child_process");
      execSync("npm install", {
        cwd: path.join(process.cwd(), answers.projectName),
        stdio: "inherit",
      });
      console.log(chalk.green("✅ Dependencies installed"));
    }
  });

program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
