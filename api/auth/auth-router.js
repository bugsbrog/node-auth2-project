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


router.post("/login", checkUsernameExists, (req, res, next) => {

    // const token = buildToken(user)
    /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
