const router = require('express').Router();
const User = require('../models/User.model');
const bcrypt = require('bcrypt');
const passport = require('passport');

// github login

router.get('/github', passport.authenticate('github'));

router.get(
    '/auth/github/callback',
    passport.authenticate('github', {
        successRedirect: '/',
        failureRedirect: '/login',
    })
);
// signup
router.get('/signup', (req, res, next) => {
    res.render('signup');
});

// login
router.get('/login', (req, res, next) => {
    res.render('login');
});

router.post(
    '/login',
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        passReqToCallback: true,
    })
);

// the signup form posts to this route

// sign up form posts to this route
router.post('/signup', (req, res, next) => {
    const { username, password } = req.body;

    if (password.length < 8) {
        res.render('signup', { message: 'Your password must be 8 character)' });
        return;
    }

    if (username === '') {
        res.render('signup', { message: 'Your username cannot be empty)' });
        return;
    }

    // check if username already exist
    User.findOne({ username: username })
        // if yes show the signup again with a message
        .then((user) => {
            if (user !== null) {
                res.render('signup', { message: 'Username is already taken)' });
            } else {
                // if pass --> create new user in DB with hashed pw
                const salt = bcrypt.genSaltSync();
                const hash = bcrypt.hashSync(password, salt);
                // create user in DB
                User.create({
                    username,
                    password: hash,
                }).then((userDB) => {
                    console.log(userDB);
                    req.login(userDB, (err) => {
                        if (err) {
                            next(err);
                        } else {
                            res.redirect('/');
                        }
                    });
                    // res.redirect('/');
                });
            }
        })
        .catch((err) => {
            console.log(err);
        });
});

router.get('/logout', (req, res) => {
    // req.logout is a passport function
    req.logout();
    res.redirect('/');
});

module.exports = router;
