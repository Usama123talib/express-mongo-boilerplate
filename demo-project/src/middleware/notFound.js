const { StatusCodes } = require('../utils/enums/httpStatus.enum');

module.exports = (req, res, next) => {
  res.status(StatusCodes.NOT_FOUND).json({
    success: false,
    message: `Cannot find ${req.originalUrl} on this server!`
  });
};