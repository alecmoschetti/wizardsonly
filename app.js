require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const router = require('express').Router();
const pino = require('pino-http');
const logger = pino({prettyPrint: true});
const crypto = require('crypto');
const session = require('express-session');
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const compression = require('compression');
const async = require('async');
const { body, validationResult } = require('express-validator');
const { DateTime } = require('luxon');
const MongoStore = require('connect-mongo');

/* app init */
const app = express();
const port = (process.env.PORT || '3000');
app.set('port', port);

/* database */
const uri = process.env.DB_STRING;
mongoose.connect(uri, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

/* session setup */
// const sessionStore = new MongoStore({ mongooseConnection: db, collection: 'sessions'});
app.use(session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true,
    store: MongoStore.create({
        mongoUrl: uri,
    }),
    cookie: {
        maxAge: (2 * 24 * 60 * 60 * 1000) 
    }
}));

/* mongoose model init */
const User = mongoose.model('User', new Schema({
    username: { type: String, required: true },
    hash: { type: String, required: true },
    salt: { type: String, required: true },
    first_name: { type: String, required: true },
    last_name: { type: String, required: true },
    email: { type: String, required: true },
    admin: { type: Boolean },
    membership: { type: Boolean }, 
    messages: [{ type: Schema.Types.ObjectId, ref: 'Message' }]
}));

const Message = mongoose.model('Message', new Schema({
    title: { type: String, required: true },
    timestamp: { type: String, required: true },
    message: { type: String, required: true },
    userID: { type: String, required: true },
    user: { type: String, required: true }
}));


/* custom middleware for locals object */
/* allows us to access the current user variable in all of our views, so we don't have to manually pass it in our controllers */
app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    next();
});

/* passport functions */

const customFields = {
    username: 'username',
    password: 'password'
};

const verify = (username, pw, done) => {
    User.findOne({ username })
        .then(user => {
            if (!user) return done(null, false);
            const isValidated = validatePassword(pw, user.hash, user.salt);
            (isValidated) ? done(null, user) : done(null, false);
        })
        .catch(err => done(err));
};

const strategy = new localStrategy(customFields, verify);

passport.use(strategy);

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((userId, done) => {
    User.findById(userId)
        .then(user => done(null, user))
        .catch(err => done(err));
});

/* functions to generate and validate hashed passwords */

function generatePassword(pw) {
    const salt = crypto.randomBytes(32).toString('hex');
    const genHash = crypto.pbkdf2Sync(pw, salt, 10000, 64, 'sha512').toString('hex');
    return {
        salt,
        hash: genHash
    };
}

function validatePassword(pw, hash, salt) {
    const verifyHash = crypto.pbkdf2Sync(pw, salt, 10000, 64, 'sha512').toString('hex');
    return hash === verifyHash;
}

/* passport init */
app.use(passport.initialize());
app.use(passport.session());

/* init views */
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

/* rest of middlewares */
app.use(logger);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(helmet());
app.use(compression());
app.use(express.static(path.join(__dirname, 'public')));

/* routing */
/* ~~~~~ GET ROUTES ~~~~~~ */

/* GET home page. */
router.get('/', function(req, res, next) {
    res.render('index', { title: 'Wizards Only', user: req.user });
  });
  
  router.get('/register', (req, res, next) => res.render('register', { title: 'Register' } ));
  
  router.get('/login', (req, res, next) => res.render('login', { title: 'Login' } ));
  
  router.get('/login_failure', (req, res, next) => res.render('login_failure'));
  
  router.get('/chat', (req, res, next) => {
    async.parallel({
      messages: cb => Message.find().sort([['timestamp', 'descending']]).populate('user').exec(cb),
    }, (err, results) => {
      if (err) return next(err);
      res.render('chat', { title: 'Wizard City', user: req.user, messages: results.messages } )
    });
  });
  
  router.get('/logout', (req, res, next) => {
    req.logout();
    res.redirect('/');
  });
  
  router.get('/:userId/message_form', (req, res, next) => res.render('message_form', { title: 'New Message', user: req.user }));
  
  router.get('/secretjoin', (req, res, next) => res.render('secretjoin', { }));
  
  router.get('/delete_message/:id', (req, res, next) => {
    async.parallel({
      message: cb => Message.findById(req.params.id).populate('userID').exec(cb),
    }, (err, results) => {
      if (err) return next(err);
      Message.findByIdAndDelete(results.message._id, err => {
        if (err) return next(err);
        res.redirect('/chat');
      })
    });
  });
  
  router.get('/admin', (req, res, next) => res.render('admin', { user: req.user } ));
  
  /* ~~~~~POST ROUTES ~~~~~~~ */
  
  router.post('/login', passport.authenticate('local', {
    successRedirect: '/chat',
    failureRedirect: '/login_failure',
    failureFlash: true,
    failureMessage: 'Invalid credentials'
  }));
  
  router.post('/register', [
    body('username').trim().isLength({ min: 1}).unescape(),
    body('password').isLength({ min: 5 }),
    body('password_confirm').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords don't match");
      } else {
        return true;
      }
    }),
    body('first_name').trim().isLength({ min: 1 }).escape(),
    body('last_name').trim().isLength({ min: 1 }).escape(),
    body('email').isEmail().normalizeEmail().custom(value => {
      return User.findOne({ 'email': value }).then(user => {
        if (user) {
          return Promise.reject('E-mail already in use');
        }
      });
    }),
    (req, res, next) => {
      const errors = validationResult(req);
      const saltHash = generatePassword(req.body.password);
      const salt = saltHash.salt;
      const hash = saltHash.hash;
  
      const newUser = new User({
        username: req.body.username,
        hash,
        salt,
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        email: req.body.email,
        admin: false,
        membership: false,
      });
  
      if (!errors.isEmpty()) {
        /* there are errors */
        res.render('register', { title: 'Register', user: newUser, errors: errors.array() });
        return;
      } else {
        newUser.save(err => err ? next(err) : res.redirect('/login'));
        return;
      }
    }
  ]);
  
  router.post('/:userId/message_form', [
    body('title').trim().isLength({ min: 1 }).unescape(),
    body('message').trim().isLength({ min: 1 }).unescape(),
    (req, res, next) => {
      const errors = validationResult(req);
      let today = new Date();
      const newMessage = new Message({
        title: req.body.title,
        timestamp: DateTime.fromJSDate(today).toLocaleString(DateTime.DATETIME_FULL),
        message: req.body.message,
        userID: req.user._id,
        user: req.user.username
      });
  
      if (!errors.isEmpty()) {
        /* there are errors */
        res.render(`/${req.user._id}/message_form`, { title: 'Register', user: req.user, errors: errors.array(), message: newMessage });
        return;
      } else {
        const updatedUser = new User({
          username: req.user.username,
          hash: req.user.hash,
          salt: req.user.salt,
          first_name: req.user.first_name,
          last_name: req.user.last_name,
          email: req.user.email,
          admin: req.user.admin,
          membership: req.user.membership,
          messages: [...req.user.messages, newMessage],
          _id: req.user._id
        });
        User.findByIdAndUpdate(req.user._id, updatedUser, {}, (err, theuser) => {
          if (err) return next(err);
          return;
        });
        newMessage.save(err => err ? next(err) : res.redirect('/chat'));
        return;
      }
    }
  ]);
  
  router.post('/secretjoin', [
    body('secret_password').trim().escape().custom(value => {
      if (value !== process.env.MEMBERSONLY_PASSWORD) {
        throw new Error('nah');
      } else {
        return true;
      }
    }),
    (req, res, next) => {
      const errors = validationResult(req);
      const updateMembership = new User({
        username: req.user.username,
        hash: req.user.hash,
        salt: req.user.salt,
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        email: req.user.email,
        admin: req.user.admin,
        membership: true,
        messages: req.user.messages,
        _id: req.user._id
      });
  
      if (!errors.isEmpty()) {
        /* there are errors */
        res.render('secretjoin', { errors: errors.array() });
        return;
      } else {
        User.findByIdAndUpdate(req.user._id, updateMembership, {}, (err, theuser) => {
          if (err) return next(err);
          res.redirect('/chat');
        });
      }
    }
  ])
  
  router.post('/admin', [
    body('admin_password').trim().escape().custom(value => {
      if (value !== process.env.ADMIN_PASSWORD) {
        throw new Error('nah');
      } else {
        return true;
      }
    }),
    (req, res, next) => {
      const errors = validationResult(req);
      const newAdmin = new User({
        username: req.user.username,
        hash: req.user.hash,
        salt: req.user.salt,
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        email: req.user.email,
        admin: true,
        membership: true,
        messages: req.user.messages,
        _id: req.user._id
      });
  
      if (!errors.isEmpty()) {
        /* there are errors */
        res.render('admin', { user: req.user, errors: errors.array() });
        return;
      } else {
        User.findByIdAndUpdate(req.user._id, newAdmin, {}, (err, theuser) => {
          if (err) return next(err);
          res.redirect('/chat');
        });
      }
    }
  ]);

app.use(router);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    next(createError(404));
  });
  
  // error handler
  app.use(function(err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
  
    // render the error page
    res.status(err.status || 500);
    res.render('error');
  });

  app.listen(port, () => console.log(`Server started on port ${port}`));