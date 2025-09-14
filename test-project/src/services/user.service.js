const User = require('../models/user.model');
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

module.exports = new UserService();