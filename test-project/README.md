# Express MongoDB Boilerplate

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

```bash
npm install
```

2. Set up environment variables:

```bash
cp .env.example .env
```

3. Update the .env file with your configuration

4. Start MongoDB locally or use MongoDB Atlas

5. Run the development server:

```bash
npm run dev
```

## Project Structure

```
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
```

## API Documentation

### Authentication Endpoints

| Method | Endpoint               | Description          | Body                                         |
| ------ | ---------------------- | -------------------- | -------------------------------------------- |
| POST   | `/api/v1/auth/signup`  | Register new user    | `{ name, email, password, confirmPassword }` |
| POST   | `/api/v1/auth/login`   | Login user           | `{ email, password }`                        |
| POST   | `/api/v1/auth/refresh` | Refresh access token | `{ refreshToken }`                           |
| POST   | `/api/v1/auth/logout`  | Logout user          | -                                            |

### User Endpoints

| Method | Endpoint                   | Description               | Auth Required |
| ------ | -------------------------- | ------------------------- | ------------- |
| GET    | `/api/v1/users`            | Get all users (paginated) | No            |
| GET    | `/api/v1/users/:id`        | Get user by ID            | No            |
| GET    | `/api/v1/users/profile/me` | Get current user profile  | Yes           |
| PUT    | `/api/v1/users/:id`        | Update user               | Yes           |
| DELETE | `/api/v1/users/:id`        | Delete user               | Yes (Admin)   |

## License

MIT

---

**Created with ❤️ using [Express MongoDB Boilerplate Generator](https://github.com/Usama123talib/express-mongo-boilerplate) by Usama Talib**
