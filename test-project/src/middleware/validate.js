const AppError = require('../utils/appError');
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

module.exports = validate;