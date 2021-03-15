const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("./users-model");
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

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
      const {username, password, role_name} = req.body;
      const user = await Users.find(username);

      if (user) {
          return res.status(409).json({message: `The username ${user.username} is already taken. Please try again.`})
      }

      const newUser = await Users.add({
        username,
        password: await bcrypt.hash(password, process.env.BCRYPT_TIME_COMPLEXITY),
        role_name
      })

      res.status(201).json(newUser);

    } catch (err) {
        next(err);
    }
})


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
      const {username, password} = req.body;
      const user = await Users.findBy({username}).first();
      const role = await Users.user.role_name;

      if(!user) {
        return res.status(401).json({message: 'Invalid Credentials'})
      }
      const validPass = await bcrypt.compare(password, user.password);

      if (!validPass) {
          return res.status(401).json({message: 'Invalid Credentials'})
      }

      const token = jwt.sign({
          userID: user.user_id,
          userRole: role,
          JWT_SECRET,
      })

      res.cookie('token', token);

      res.json({message: `Welcome, ${user.username}!`})

    } catch (err) {
        next(err);
    }
});

module.exports = router;
