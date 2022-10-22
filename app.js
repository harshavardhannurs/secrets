//Authentication
//Level-1 The passwords are stored in plaintext in the database
//Level-2 Encryption-Basically all it is is just scrambling something and it requires a key to unscramble it.
//In cryptography, it is the process of encoding information. This process converts the original representation of the information, known as plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information.
//The earliest form of encryption is "Caesar Cipher" where the key would be the number of letters you would shift by for ex: A would be C where the key being 2.
//The encryption we have used is an npm package called "mongoose-encryption".
//Level-3 Hide the confidential parts in the code(For eg:API keys or secret) using environment variables
require('dotenv').config();//should require dotenv at the very start
const express = require('express')
const app = express();
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const encrypt = require("mongoose-encryption")

app.set('view engine', 'ejs')
app.use(express.static("public"))
app.use(bodyParser.urlencoded({extended:true}))

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true})

const userSchema = new mongoose.Schema({
  email:String,
  password:String
})

//console.log(process.env.SECRET);Accessing environment variables
//secret is in .env
//The way we add environment variables in .env is in the form, NAME=VALUE or NAME_XYZ=VALUE
userSchema.plugin(encrypt, {secret:process.env.SECRET, encryptedFields:['password']})//You have to add this before you create a model
//Schemas are pluggable, that is, they allow for applying pre-packaged capabilities to extend their functionality.


const User = mongoose.model("User", userSchema);

app.get("/", (req, res)=>{
  res.render("home")
})

app.get("/login", (req, res)=>{
  res.render("login")
})

app.get("/register", (req, res)=>{
  res.render("register")
})

app.post("/register", (req, res)=>{
  const newUser = new User({
    email:req.body.username,
    password:req.body.password
  });
  newUser.save((err)=>{//mongoose encrypts when we use save()
    if(!err){res.render("secrets")}else{console.log(err);}
    //We will only send users to secrets page after they register0 or login
  });
});

app.post("/login", (req, res)=>{
  const emailEntered = req.body.username;
  User.findOne({email:emailEntered}, (err, foundUser)=>{
    if(foundUser){
      if(req.body.password === foundUser.password){//mongoose decrypts when we use find()
        res.render("secrets")
      }else{
        console.log("Incorrect password");
      }
    }else{
      console.log(err);
    }
  });
});

app.listen(3000, ()=>{
  console.log("server running on port 3000");
})
