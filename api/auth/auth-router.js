const router = require("express").Router();
const bcrypt = require('bcryptjs');
const {
    checkUsernameExists,
    validateRoleName
} = require('./auth-middleware');
const buildToken = require('./auth-token-builder')

const Users = require('../users/users-model')
const { BCRYPT_ROUNDS } = require('.././secrets/index')

router.post("/register", validateRoleName, async (req, res, next) => {
    const { username, password } = req.body
    const { role_name } = req
    const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS)
        try {
            const addUser = await Users.add({ username, password: hash, role_name })
            res.status(201).json(addUser)
        } catch (err) {
            next(err)
        }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
    const { password } = req.body
        if (bcrypt.compareSync(password, req.user.password)) {
            const token = buildToken(req.user)
                res.json({
                    message: `${req.user.username} is back!`,
                    token,
                })
            } else {
                next({
                    status: 401,
                    message: 'Invalid credentials'
                })
            }
});

module.exports = router;
