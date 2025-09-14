# Express MongoDB Boilerplate Generator

A powerful CLI tool to generate production-ready Express.js and MongoDB applications with service layer architecture, Joi validation, and industry best practices.

## 🚀 Installation

```bash
npm install -g express-mongo-boilerplate-generator
```

Or use with npx (recommended):

```bash
npx express-mongo-boilerplate-generator create my-app
```

## ⚡ Quick Start

### Create a new project:

```bash
create-express-mongo-app create my-awesome-api
```

### Interactive mode:

```bash
create-express-mongo-app init
```

## ✨ Features

- ✅ **Service Layer Architecture** - Clean separation of concerns
- ✅ **Joi Validation** - Robust request validation
- ✅ **JWT Authentication** - Secure token-based auth
- ✅ **MongoDB with Mongoose** - Modern ODM
- ✅ **Organized Enums** - Centralized constants
- ✅ **Error Handling** - Custom error classes
- ✅ **Docker Support** - Ready for containerization
- ✅ **Testing Setup** - Jest with in-memory MongoDB
- ✅ **ESLint & Prettier** - Code quality tools
- ✅ **Security** - Helmet, CORS, Rate limiting

## 📁 Generated Project Structure

```
my-app/
├── src/
│   ├── controllers/      # HTTP request handlers
│   ├── services/         # Business logic layer
│   ├── routes/           # API endpoints
│   ├── models/           # Mongoose schemas
│   ├── validators/       # Joi validation schemas
│   ├── middleware/       # Custom middleware
│   ├── utils/
│   │   └── enums/       # Enum constants
│   ├── app.js           # Express app setup
│   └── server.js        # Server entry point
├── __tests__/           # Test files
├── .env                 # Environment variables
├── .env.example         # Environment template
├── docker-compose.yml   # Docker compose config
├── Dockerfile          # Docker configuration
├── package.json
└── README.md
```

## 🛠️ CLI Options

```bash
create-express-mongo-app create <project-name> [options]

Options:
  -g, --git      Initialize git repository
  -i, --install  Install dependencies automatically
  -h, --help     Display help
  -V, --version  Output version number
```

## 📋 Requirements

- Node.js >= 14.0.0
- npm >= 6.0.0
- MongoDB (local or Atlas)

## 🏗️ Architecture

The generated boilerplate follows **Service Layer Architecture**:

- **Routes** → Define endpoints
- **Controllers** → Handle HTTP only
- **Services** → Business logic & DB operations
- **Validators** → Joi request validation
- **Models** → Mongoose schemas
- **Enums** → Centralized constants

## 🔧 Usage Example

After generating your project:

```bash
# Navigate to project
cd my-awesome-api

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env

# Start development server
npm run dev
```

Your API will be running at `http://localhost:3000`

## 🌟 What's Included

- User authentication system
- JWT token management
- Request validation with Joi
- Error handling middleware
- MongoDB connection management
- Pagination support
- Security best practices
- Docker configuration
- Testing setup
- ESLint configuration

## 📝 License

MIT

## 👨‍💻 Author

**Usama Talib**

- Email: talibusama1234@gmail.com
- GitHub: [@usamatalib](https://github.com/Usama123talib)

## 🤝 Contributing

Issues and pull requests are welcome!

## 🔗 Links

- [GitHub Repository](https://github.com/Usama123talib/express-mongo-boilerplate)
- [NPM Package](https://www.npmjs.com/package/express-mongo-boilerplate-generator)
- [Report Issues](https://github.com/Usama123talib/express-mongo-boilerplate/issues)

---

Made with ❤️ by Usama Talib
