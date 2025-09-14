const Joi = require('joi');
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
};