const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets");

function buildToken(user) {
    const payload = {
        // copy-pasta will be the death of me! I had
        // subject: user.id instead of user.user_id
        subject: user.user_id,
        username: user.username,
        role_name: user.role_name
    }
    const options = {
        expiresIn: '1d'
    }

    return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = buildToken