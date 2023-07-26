const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const Users = require('../users/users-model')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

    try {
    let { username, password } = req.body
    
    const hash = bcrypt.hashSync(password, 10)

    password = hash

    const { role_name } = req

    const newUser = await Users.add({username, password, role_name})
    res.status(201).json(newUser)
    } catch(err){
      next(err)
    }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
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

    try {
     if (bcrypt.compareSync(req.body.password, req.user.password)){
      const token = buildToken(req.user)
      res.json({
          message: `${req.user.username} is back!`,
          token,
        })
     } else (
      next({status: 401, message: "Invalid credentials"})
     )

  }catch(err){
  next(err)
 }
});

const buildToken = (user) => {
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
