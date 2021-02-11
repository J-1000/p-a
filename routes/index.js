const router = require('express').Router();

const loginCheck = () => {
    return (req, res, next) => {
        // in node-basic-auth: req.session.user
        // req.isAuthenticated() -> this is a passport function
        if (req.isAuthenticated()) {
            next();
        } else {
            res.redirect('/login');
        }
    };
};

// in node basic auth the user is in req.session.user
// in passport the user is in req.user

/* GET home page */
router.get('/', (req, res, next) => {
    const user = req.user
    console.log(user);
    res.render('index', { user: req.user });
});

router.get('/private', loginCheck(), (req, res) => {
    res.render('private');
});

module.exports = router;
