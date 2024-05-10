// models/user.js
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const config = require('../config');
const LogManager = require('../LogManager');
const log = new LogManager(config);

// Extract database configuration from the config object
const { host, user, password, database } = config.database;

const sequelize = new Sequelize(database, user, password, {
  dialect: 'mysql',
  host: host
});

const User = sequelize.define('User', {
  firstName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  role: {
    type: DataTypes.ENUM('user', 'admin'),
    defaultValue: 'user'
  },
  data: {
    type: DataTypes.JSONB,
    allowNull: true
  }
}, {
    hooks: {
      beforeCreate: async (user) => {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(user.password, saltRounds);
        user.password = hashedPassword;
      }
    },
    // Define static methods for user operations
    classMethods: {
      findByEmail: function(email) {
        return this.findOne({ where: { email: email } });
      },
      findByUsername: function(username) {
        return this.findOne({ where: { username: username } });
      },
      verifyPassword: async function(password, hashedPassword) {
        return await bcrypt.compare(password, hashedPassword);
      }
      // Add more helper functions as needed
    }
  });
  
  User.createUser = async function(firstName, lastName, username, email, password) {
    try {
      // Create a new user
      const newUser = await User.create({
        firstName: firstName,
        lastName: lastName,
        username: username,
        email: email,
        password: password
      });
  
      log.info('User created successfully:', newUser.toJSON());
    } catch (error) {
      log.error('Error creating user:', error);
    }
  }
  
  User.findUserByEmail = async function(email) {
    try {
      // Find a user by email
      const user = await User.findByEmail(email);
      if (user) {
        log.info('User found:', user.toJSON());
      } else {
        log.info('User not found');
      }
    } catch (error) {
      log.error('Error finding user by email:', error);
    }
  }
  
  User.findUserByUsername = async function(username) {
    try {
      // Find a user by username
      const user = await User.findByUsername(username);
      if (user) {
        log.info('User found:', user.toJSON());
      } else {
        log.info('User not found');
      }
    } catch (error) {
      log.error('Error finding user by username:', error);
    }
  }
  
  User.verifyUserPassword = async function(email, password) {
    try {
      // Find the user by email
      const user = await User.findByEmail(email);
      if (user) {
        // Verify the password
        const isPasswordValid = await User.verifyPassword(password, user.password);
        if (isPasswordValid) {
            log.info('Password is valid');
        } else {
            log.info('Password is invalid');
        }
      } else {
        log.info('User not found');
      }
    } catch (error) {
      log.error('Error verifying user password:', error);
    }
  }

module.exports = User;
