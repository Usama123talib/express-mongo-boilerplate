const express = require('express');
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

module.exports = router;