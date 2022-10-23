//Authentication
//Level-1 The passwords are stored in plaintext in the database

//Level-2 Encryption-Basically all it is is just scrambling something and it requires a key to unscramble it.
//In cryptography, it is the process of encoding information. This process converts the original representation of the information, known as plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information.
//The earliest form of encryption is "Caesar Cipher" where the key would be the number of letters you would shift by for ex: A would be C where the key being 2.
//The encryption we have used is an npm package called "mongoose-encryption".

//Level-3 Hide the confidential parts in the code(For eg:API keys or secret) using environment variables

//Level-4 Hashing: password --hash fn---> hash and we store that hash in our database. Hash functions are mathematical eqns that are designed to make it almost impossible to go backwards(i.e., hash to password). We have used md5 for hashing
//Note: We always have to know that the same passwords turns to be same hash
//Salting: password + random set of chars(salt) ---hash fn--> hash. Salt is stored in the database along with hash
//"bcrypt" is an another hasing function which is more secure. It allows us to hash passwords and compare hashed passowrd with the entered one
//In bcrypt we also have "salt rounds" i.e., the number os times the hash is salted
//pass + salt --bcrypt--> hash + same salt --bcrypt--> hash...
//bcrypt is very sensitive about the node version so make sure to first install nvm(node version manager) is not installed and then update or downgrade the node(nvm i node_version)

//Level-5 Authentication
//What are cookies?
//Cookies are pieces of data that are stored inside the browser. While the cookies itself don't contain any info about what the user did but it contains id number that is used to fetch the user's activity in that browsing session.
//Suppose we have to buy an item from amazon,
//1.First we make a GET request to amazon server.
//2.The server sends the HTML, CSS and JS files to the user's browser as RESPONSE
//3.Let's say that we add an item on the cart. Now this is equivalent of making a POST request to amazon server.
//4.The server now generates a cookie and send it back to browser as a RESPONSE instructing the browser to save the cookie.
//5.Now that means that if we get distracted and go on to do something else rather than finishing the purchase with payment,
//at a later time when we go to amazon(by making GET request), the browser sends the cookie along with the GET,
//which allows the server to identify the user and their previous sessions, revealing user's previous activities.
//The amazon again sends HTML, CSS, JS files as RESPONSE along with rendering the cart using the cookie info.

//Session: The period of time the browser interacts with the server.
//1.User submits login form to a server
//2.Server validates it and creates a session in the DB and responds with a sessionID.
//3.Browser puts sessionID in cookies.
//4.Browser sends cookies with future requests
//We are going to incorporate hashing, salting and authentication using passport.

//Level-6 Third party OAuth

require('dotenv').config();//should require dotenv at the very start
const express = require('express')
const app = express();
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const encrypt = require("mongoose-encryption")
const md5 = require('md5'); //We no more need mongoose-encryption if we are using md5
const bcrypt = require('bcrypt');//We no more need md5 if we are using bcrypt
const saltRounds = 10;
const session = require('express-session')  //require this first
const passport = require('passport') //We no more need bcrypt if we are using passport
const passportLocalMongoose= require('passport-local-mongoose')
//Note that we have installed passport-local package too


app.set('view engine', 'ejs')
app.use(express.static("public"))
app.use(bodyParser.urlencoded({extended:true}))

app.use(session({
  secret: process.env.NEW_SECRET,
  resave: false,
  saveUninitialized: false,
}))

app.use(passport.initialize());
//Passport is an authentication middleware for Node that authenticates requests.
//So basically passport.initialize() initialises the authentication module.
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true})

const userSchema = new mongoose.Schema({
  email:String,
  password:String
})

userSchema.plugin(passportLocalMongoose)//Used to hash and salt the password and save our users into MongoDB database

//console.log(process.env.SECRET);Accessing environment variables
//secret is in .env
//The way we add environment variables in .env is in the form, NAME=VALUE or NAME_XYZ=VALUE

//userSchema.plugin(encrypt, {secret:process.env.SECRET, encryptedFields:['password']})//You have to add this before you create a model

//Schemas are pluggable, that is, they allow for applying pre-packaged capabilities to extend their functionality.

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());//create local login strategy
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
//Serialize and deserialize is only necessary when we are using sessions.
//Serialize creates a cookie and stuffs messages like user identification into that cookie
//Deserialize allows the passport to discover messages in that cookie.

app.get("/", (req, res)=>{
  res.render("home")
})

app.get("/login", (req, res)=>{
  res.render("login")
})

app.get("/register", (req, res)=>{
  res.render("register")
})

app.get("/secrets", (req, res)=>{ //if the user is authenticated, then he/she can directly go to secrets route
  if(req.isAuthenticated()){
    res.render("secrets")
  }else{
    res.redirect("/login")
  }
})

app.get("/logout", (req, res)=>{
  req.logout((err)=>{
    if(!err){res.redirect("/")}else{console.log(err);}
  })
});

app.post("/register", (req, res)=>{
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email:req.body.username,
  //     password:hash
  //   });
  //   newUser.save((err)=>{//mongoose encrypts when we use save()
  //     if(!err){res.render("secrets")}else{console.log(err);}
  //     //We will only send users to secrets page after they register or login
  //   });
  // });
  User.register({username:req.body.username}, req.body.password, (err, user)=>{//register() comes from passport-local-mongoose> This eliminates the hassle of creating a new user, saving the new user, etc
    if(err){
      console.log(err);
      res.redirect("/")
    }else{
      passport.authenticate("local")(req, res, ()=>{//callback only triggers if authentication was successful
        res.redirect("/secrets")
      })
    }
  })

});

app.post("/login", (req, res)=>{
  // const emailEntered = req.body.username;
  // User.findOne({email:emailEntered}, (err, foundUser)=>{
  //   if(foundUser){
  //       // if(md5(req.body.password) === foundUser.password){//mongoose decrypts when we use find()
  //       bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
  //         if(result === true){
  //           res.render("secrets")
  //         }else{
  //           console.log("Incorrect password");
  //         }
  //       });
  //   }else{
  //     console.log("Invalid user");
  //     console.log(err);
  //   }
  // });
  const user = new User({
    username:req.body.username,
    password:req.body.password
  });
  req.login(user, (err)=>{ //login() comes form passport package
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req, res, ()=>{
        res.redirect("/secrets")
      })
    }
  })
});

//Now note that though hashes are quiet secure, hashes are till hackable
//Suppose a user has kept a word in dictionary as password. We have around 150,000 words in a dictionary and he only has to hash those many words to find the password(dictionary attack)
//Similarly all the numbers from a telephone book,etc. But today's GPUs can calculate around 20000000 hashes in a single second so the chances of users with common passwords getting hacked is very high.
//Now as a solution a password should be lengthy (>6) and must also contain special characters, numbers, uppercase letters etc(i.e., a strong password)
app.listen(3000, ()=>{
  console.log("server running on port 3000");
})
