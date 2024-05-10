var createError = require('http-errors');
var express = require('express');
const config = require('./config');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const fs = require('fs');
const LogManager = require('./LogManager');

const log = new LogManager(config);

var indexRouter = require('./routes/index');

// MySQL session store options
const sessionStore = new MySQLStore({
  host: config.database.host,
  port: 3306,
  user: config.database.user,
  password: config.database.password,
  database: config.database.database,
  createDatabaseTable: true // Automatically create session table if not exists
});

log.info('MySQL Session store created');

var app = express();

// Session middleware
app.use(session({
  key: config.sessionName,
  secret: config.sessionSecret,
  store: sessionStore,
  resave: false,
  saveUninitialized: false
}));

log.debug('Session middleware initialized');

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// Config Declarations
app.locals.config = config;
log.debug('Configurations attached to app.locals');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);

log.debug('Express app initialized and indexRouter attached to / route');

// Search and Define Routes by reading files in the routes folder
fs.readdirSync(path.join(__dirname, 'routes')).forEach(file => {
  // Skip if it's not a JavaScript file or if it's the current file (app.js)
  if (file === 'index.js' || !file.endsWith('.js')) return;

  // Require the route file
  const route = require(`./routes/${file}`);

  // Extract the base route from the filename (e.g., dashboard.js becomes /dashboard)
  const baseRoute = `/${path.parse(file).name}`;

  // Log the route
  log.info(`Attaching route ${baseRoute}`);

  // Use the route in the Express app
  app.use(baseRoute, route);
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // Log the error
  log.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
