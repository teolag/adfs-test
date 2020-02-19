const express = require('express')
const passport = require('passport')
const OidcStrategy = require('passport-openidconnect').Strategy;
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

passport.use('ocd', new OidcStrategy({
  issuer: `https://adfs-test.vgregion.se/adfs`,
  authorizationURL: `https://adfs-test.vgregion.se/adfs/oauth2/authorize/`,
  tokenURL: `https://adfs-test.vgregion.se/adfs/oauth2/token/`,
  userInfoURL: `https://adfs-test.vgregion.se/adfs/userinfo`,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.REDIRECT_URL,
  resource: 'medlo-local',
  scope: `openid email profile allatclaims medlo-local`,
}, function (issuer, sub, profile, jwtClaims, accessToken, refreshToken, tokenResponse, done) {
  console.log(issuer, sub, profile, jwtClaims, tokenResponse)
  done(null, profile);
}))


app.get("/login", passport.authenticate('ocd'))

app.get('/api/auth/adfs', passport.authenticate('ocd'), (req, res) => {
  res.json({message: 'Inne!', body: req.body, user: req.user})
})

app.listen(process.env.PORT, () => console.log(`Server started on port: ${process.env.PORT}`))
