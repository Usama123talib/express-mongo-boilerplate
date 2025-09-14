const express = require('express');
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

module.exports = router;