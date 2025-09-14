const userService = require('../services/user.service');
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

module.exports = new UserController();