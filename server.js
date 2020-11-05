const express = require('express');
const bcrypt = require('bcryptjs');
const mongoose = require("mongoose")
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const auth = require("./auth");

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

//DB
mongoose.connect('mongodb://localhost:27017/RBA-DB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
});

const userSchema = mongoose.Schema({
  firstname: {
    type: String,
    required: true,
    trim: true,
  },
  lastname: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 7
  },
  subjects: {
    type: Array
  },
  token: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['student', 'tutor', 'admin'],
    default: 'student'
  }, 
});


const User = mongoose.model("User", userSchema);


// Routes
app.get('/signup', (req, res) => {
  res.send('Sign up page')
})

app.post('/signup', async (req, res) => {
  
  const {firstname, lastname, email, password, role} = req.body;
  
  // Validation and error checks
  if(!firstname || !lastname || !email || !password) {
   res.status(200).send("All fields are required boss"); 
  }
   const userExistInDB = await User.findOne({email});
   if(userExistInDB) {
     res.status(401).send("Email is already in use.");
   } else {
     const user = new User({
       firstname, lastname, email, password, role
     })
     // generate token
     const accessToken = jwt.sign({email, userId: user._id}, 'secret', {expiresIn: '24hr'});
     user.token = accessToken;

    //  password encryption
     bcrypt.genSalt(10, (err, salt) => {
       bcrypt.hash(user.password, salt, (err, hash) => {
         user.password = hash;

         //saving user to DB
         user.save((err, success) => {
           if(err) {
             res.status(400).send(err);
           } else {
             res.status(200).send({
               message: "Success!",
               data: {
                 info: success,
               }
             })
           }
         })
       })
     })
   }
});

app.post("/login", async (req, res) => {
  try {
    const {email, password} = req.body

    let user = await User.findOne({email})
    if(!user) {
      res.status(400).send("Email doesn't exist!");
    }

    const validPass = await bcrypt.compare(password, user.password);
    if(!validPass) {
      res.status(400).send("Incorrect password!");
    } else {
      
    const accessToken = jwt.sign({email, userId: user._id, role: user.role}, 'secret', {expiresIn: '10hr'});
    const result = await User.findByIdAndUpdate(user._id, {token: accessToken}, {useFindAndModify: false, new: true})
    res.header('x-auth-token', accessToken).status(200).send({
      success: "success",
      data: {
        message: "Login succesful",
        _id: result.id,
        token: result.token
      }
    })

    }

  } catch (error) {
    res.status(401).send(error) 
  }
})

app.get("/admin", auth, (req, res) => {
  if(!req.user) {
    return res.status(401).send('Please You have to login first!')
  }
  if(req.user.role === 'tutor') {
    const result = User.findByIdAndUpdate(req.user._id, {role: 'admin'}, {useFindAndModify: false}, (err, success) => {
      if(err) throw err;
      else {
        res.status(200).send({
          status: success,
          data: {
            message: `Congrats ${result.email} you're now and Admin`,
            role: result.role
          }
        })
      }
    })
  } else if(req.user.role == 'admin') {
    res.status(403).send("Invalid request, you're already an admin")
  } else {
    res.status(400).send("request Denied, you've to be a tutor")
  }
})

// Listening port
app.listen(4000, () => {
  console.log("Server is running on port 4000");
})