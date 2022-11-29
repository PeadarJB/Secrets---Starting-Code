require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook');
const findOrCreate = require('mongoose-findorcreate');
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// const md5 = require("md5")
// const encrypt = require("mongoose-encryption");

const app = express();



app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

// Connect and create mongodb database
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: Array,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Adding encryption to the password field in the userSchema
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

// use static authenticate method of model in LocalStrategy
const LocalStrategy = require('passport-local');
passport.use(new LocalStrategy(User.authenticate()));

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id);
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    // authorizationURL: 'https://www.example.com/oauth2/authorize',
    // tokenURL: 'https://www.example.com/oauth2/token',
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// passport.use(new FacebookStrategy({
//     clientID: process.env['FACEBOOK_APP_ID'],
//     clientSecret: process.env['FACEBOOK_APP_SECRET'],
//     callbackURL: "http://localhost:3000/auth/faceboook/secrets"
//   },
//   function(accessToken, refreshToken, profile, cb) {
//     console.log(profile);
//     User.findOrCreate({ googleId: profile.id }, function (err, user) {
//       return cb(err, user);
//     });
//   }
// ));

app.get("/", function(req, res) {
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: 'profile' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });

  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  // app.get('/auth/facebook',
  //   passport.authenticate('facebook', { scope: 'profile' }),
  //   function(req, res) {
  //     // Successful authentication, redirect home.
  //     res.redirect('/');
  //   });
  //
  //   app.get('/auth/facebook/secrets',
  //   passport.authenticate('facebook', { failureRedirect: '/login' }),
  //   function(req, res) {
  //     // Successful authentication, redirect home.
  //     res.redirect('/secrets');
  //   });

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("register");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret.push(submittedSecret);
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  // res.render("logout");
  res.redirect("/");
});

// Send users to the "secrets" page if password matches in DB
app.post("/register", function(req, res) {

  User.register({username:req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  }
);
});



app.post("/login", function(req, res) {

  const user = new User ({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
    });
  }
  });

});


app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
