
const express = require('express');
const passport = require('passport');
const router = express.Router();

const moment = require('moment');
const bcrypt = require('bcryptjs');

const {
    User,
    validateUser,
    confirmPassword
} = require('../models/user');

const {
    ensureAuthenticated,
    isAdmin,
    isLoggedIn,
    readAccessControl,
    createAccessControl,
    updateAccessControl,
    deleteAccessControl
} = require('../helpers/auth');

// Helper to render the signup page with errors.
function renderSignup(res, errors, body) {
    return res.status(400).render('users/signup', {
        title: 'Sign up',
        breadcrumbs: false,
        layout: 'signin',
        errors: errors,
        body: body
    });
}

// GET Signin Route.
router.get('/signin', isLoggedIn, (req, res) => {
    res.render('users/signin', {
        title: 'Please Sign in',
        breadcrumbs: false,
        layout: 'signin'
    });
});

// POST Signin Route.
router.post('/signin', isLoggedIn, (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        successFlash: true,
        failureRedirect: '/users/signin',
        failureFlash: true
    })(req, res, next);
});

// Signout Route.
router.get('/signout', ensureAuthenticated, (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }

        req.flash(
            'success_msg',
            'You have successfully signed out of the application.'
        );

        res.redirect('/users/signin');
    });
});

// GET Signup Route.
router.get('/signup', isLoggedIn, (req, res) => {
    res.render('users/signup', {
        title: 'Sign up',
        breadcrumbs: false,
        layout: 'signin'
    });
});

// POST Signup Route.
router.post('/signup', isLoggedIn, async (req, res) => {
    try {
        const { error } = validateUser(req.body);

        if (error) {
            return renderSignup(
                res,
                [{ text: error.details[0].message }],
                req.body
            );
        }

        if (confirmPassword(req.body.password, req.body.password2)) {
            return renderSignup(
                res,
                [{ text: 'Passwords do not match!' }],
                req.body
            );
        }

        const existingUser = await User.findOne({
            email: req.body.email
        });

        if (existingUser) {
            return renderSignup(
                res,
                [{ text: 'Email address already exists!' }],
                req.body
            );
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(
            req.body.password,
            salt
        );

        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            role: req.body.role,
            isAdmin: false,
            request: false,
            created: moment().format('LL')
        });

        await user.save();

        req.flash(
            'success_msg',
            'Registration submitted successfully. Awaiting admin approval.'
        );

        return res.redirect('/users/signin');

    } catch (err) {
        console.error('Registration error:', err);

        return renderSignup(
            res,
            [{ text: 'Registration failed. Please try again.' }],
            req.body
        );
    }
});

// Protected Routes.

// GET Users.
router.get(
    '/',
    [ensureAuthenticated, isAdmin],
    async (req, res, next) => {
        try {
            const perPage = 5;
            const page = Math.max(1, parseInt(req.query.page, 10) || 1);
            const skip = (perPage * page) - perPage;

            const users = await User.find({
                request: true
            })
                .skip(skip)
                .limit(perPage)
                .select({
                    name: 1,
                    email: 1,
                    role: 1,
                    created: 1,
                    isAdmin: 1,
                    'privileges.read': 1,
                    'privileges.create': 1,
                    'privileges.update': 1,
                    'privileges.delete': 1
                });

            const totalPages = await User.countDocuments({
                request: true
            });

            const pendingRequests = await User.countDocuments({
                request: false
            });

            return res.render('users/index', {
                title: 'Users',
                breadcrumbs: true,
                users: users,
                pendingRequests: pendingRequests,
                current: page,
                pages: Math.ceil(totalPages / perPage)
            });
        } catch (err) {
            return next(err);
        }
    }
);

// DELETE User.
router.delete(
    '/:id',
    [ensureAuthenticated, isAdmin, deleteAccessControl],
    async (req, res, next) => {
        try {
            await User.deleteOne({ _id: req.params.id });

            req.flash('success_msg', 'Record deleted successfully.');
            return res.send('/users');
        } catch (err) {
            return next(err);
        }
    }
);

// GET Registration Requests.
router.get(
    '/requests',
    [ensureAuthenticated, isAdmin, readAccessControl],
    async (req, res, next) => {
        try {
            const requests = await User.find({ request: false });

            return res.render('users/requests', {
                title: 'Requests',
                breadcrumbs: true,
                requests: requests
            });
        } catch (err) {
            return next(err);
        }
    }
);

// APPROVE Registration Request.
router.put(
    '/requests/:id',
    [ensureAuthenticated, isAdmin, updateAccessControl],
    async (req, res, next) => {
        try {
            const result = await User.updateOne(
                { _id: req.params.id },
                { $set: { request: true } }
            );

            if (result.matchedCount > 0) {
                req.flash('success_msg', 'Registration approved!');
            } else {
                req.flash('error_msg', 'User request not found.');
            }

            return res.redirect('/users/requests');
        } catch (err) {
            return next(err);
        }
    }
);

// DELETE Registration Request.
router.delete(
    '/requests/:id',
    [ensureAuthenticated, isAdmin, deleteAccessControl],
    async (req, res, next) => {
        try {
            await User.deleteOne({ _id: req.params.id });

            req.flash('success_msg', 'Request deleted successfully!');
            return res.send('/users/requests');
        } catch (err) {
            return next(err);
        }
    }
);

// GET Edit User Account.
router.get(
    '/edit/:id',
    [ensureAuthenticated, isAdmin, updateAccessControl],
    async (req, res, next) => {
        try {
            const result = await User.findById(req.params.id).select({
                name: 1,
                email: 1,
                role: 1,
                isAdmin: 1,
                privileges: 1
            });

            if (result) {
                return res.json(result);
            }

            return res.status(404).send('Resource not found.');
        } catch (err) {
            return next(err);
        }
    }
);

// UPDATE User Account.
router.put(
    '/edit/:id',
    [ensureAuthenticated, isAdmin, updateAccessControl],
    async (req, res, next) => {
        try {
            const result = await User.updateOne(
                { _id: req.params.id },
                {
                    $set: {
                        name: req.body.name,
                        email: req.body.email,
                        role: req.body.role,
                        isAdmin: req.body.isAdmin,
                        'privileges.read': req.body.read,
                        'privileges.create': req.body.create,
                        'privileges.update': req.body.update,
                        'privileges.delete': req.body.delete
                    }
                }
            );

            if (result.matchedCount > 0) {
                req.flash('success_msg', 'User account updated successfully.');
                return res.json('/users');
            }

            req.flash('error_msg', 'User not found.');
            return res.status(404).json('/users');
        } catch (err) {
            return next(err);
        }
    }
);

module.exports = router;
