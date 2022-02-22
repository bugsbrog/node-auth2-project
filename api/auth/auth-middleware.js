const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets");
const User = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization
    if (token) {
      jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
          next({
            status: 401,
            message: 'Token invalid'
          })
        } else {
            req.decodedJwt = decoded
            next()
          }
      })
    } else {
        next({
          status: 401,
          message: 'Token required'
        })
    }
}

const only = role_name => (req, res, next) => {
  if (req.decodedJwt.role_name === role_name) {
    next()
  } else {
      next({
        status: 403,
        message: 'This is not for you'
      })
  }
}

const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body
    try {
      const [user] = await User.findBy({ username })
        if (!user) {
          next({
            status: 401,
            message: 'Invalid credentials'
          })
        } else {
            // Why do we need this to pass 5 tests?
            // Maybe to make the password be defined? Because without it, the test says req.user.password is undefined
            req.user = user
            next()
        }
    } catch (err) {
        next(err)
    }
}

const validateRoleName = (req, res, next) => {
  const { role_name } = req.body
      if (!role_name || !role_name.trim()) {
          req.role_name = 'student'
          next()
      } else if (role_name.trim() === 'admin') {
          next({
            status: 422,
            message: 'Role name can not be admin'
          })
      } else if (role_name.trim().length > 32) {
          next({
            status: 422,
            message: 'Role name can not be longer than 32 chars'
          })
      } else {
          req.role_name = role_name.trim()
          next()
      }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
