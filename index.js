const express = require('express')
const passport = require('passport')
const {Issuer, Strategy} = require('openid-client')
const dotenv = require('dotenv')
const session = require('express-session')
const app = express()
dotenv.config()

app.use(session({secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true}))
app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser(function(user, next) {
  next(null, user)
})

passport.deserializeUser(function(user, next) {
  next(null, user)
})

Issuer.discover(process.env.DISCOVERY_URL).then(function(issuer) {
  const client = new issuer.Client({
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uris: [process.env.REDIRECT_URL]
  })
  const params = {
    /*resource: 'medlo-local',*/
    scope: 'openid email profile allatclaims'
  }

  passport.use('oidc', new Strategy({client, params}, (tokenset, user, done) => {
    console.log('Response from ADFS:', tokenset, user)
    return done(null, user)
  }))
})

app.get("/login", passport.authenticate('oidc'))

app.get('/api/auth/adfs', passport.authenticate('oidc'), (req, res) => {
  res.json({message: 'Inne!', body: req.body, user: req.user})
})

app.listen(process.env.PORT, () => console.log(`Server started on port: ${process.env.PORT}`))
