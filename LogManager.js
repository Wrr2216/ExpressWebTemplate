// LogManager.js
const fs = require('fs');
const path = require('path');

class LogManager {
    constructor(config) {
        this.config = config;

        // Create log directory if it doesn't exist
        const logDir = path.join(__dirname, 'log');
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir);
        }

        // Generate log file path
        const currentDate = new Date().toISOString().replace(/:/g, '-').replace('T', '_').split('.')[0];
        this.logFilePath = path.join(logDir, `app_${currentDate}.log`);
    }

    log(type, message) {
        // Create a timestamp
        const timestamp = new Date().toISOString();

        // Format the log message
        const logMessage = `[${timestamp}] [${type.toUpperCase()}]: ${message}\n`;

        // Write to the log file
        fs.appendFile(this.logFilePath, logMessage, err => {
            if (err) {
                console.error('Error writing to log file:', err);
            }
        });

        // Log to the console as well
        console.log(logMessage);
    }

    debug(message) {
        if (this.config.logLevel === 'dev') {
            this.log('debug', message);
        }
    }

    info(message) {
        this.log('info', message);
    }

    warn(message) {
        this.log('warning', message);
    }

    error(message) {
        this.log('error', message);
    }
}

module.exports = LogManager;
