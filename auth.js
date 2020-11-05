const jwt = require('jsonwebtoken');
const User = require("./auth");

const auth = async(req, res, next) => {
  if(req.headers['x-access-token'] || req.headers.authorization) {
    const token = await req.headers['x-access-token'] || await req.headers.authorization.replace('Bearer', '')

    try {
      const data = jwt.verify(token, 'secret');
      const user = await User.findOne({token})

      if(!user) {
        throw new Error()
      }

      req.user = user;
      req.token = token;
      next()

    } catch (error) {
      res.status(400).send("Not Authorized to access this resource");
    }

  } else {
    return res.status(401).send("FORBIDDEN..");
  }
}

module.exports = auth;