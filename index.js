const express = require('express')
const passport = require('passport')
const {Issuer, Strategy} = require('openid-client')
const dotenv = require('dotenv')
const session = require('express-session')
const app = express()
const jwtDecode = require('jwt-decode');
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

app.use(express.urlencoded({extended: true}))
app.use(express.json())

app.use((req, res, next) => {
  console.log("LOGG:", req.method, req.url)
  next()
})
app.get("/login/vgr", passport.authenticate('vgr'))
app.post('/api/auth/adfs', (req, res) => {
  // VALIDATE ID_TOKEN!!!
  // USE NONCE !!!!
  const idTokenData = jwtDecode(req.body.id_token)
  console.log({url: req.url, query:req.query, body:req.body, headers: req.headers, user: req.user, idTokenData})
  const user = jwtDecode(req.body.id_token)
  res.send("<pre>" + JSON.stringify(user, null, 2) + "</pre>")
})

app.get("/login/google", passport.authenticate('google'))
app.get('/api/auth/google', passport.authenticate('google'), (req, res) => {
  res.json({message: 'Inne Google!', body: req.body, user: req.user})
})

app.get("/login/microsoft", passport.authenticate('microsoft'))
app.get('/api/auth/microsoft', passport.authenticate('microsoft'), (req, res) => {
  res.json({message: 'Inne Microsoft!', body: req.body, user: req.user})
})

app.get("*", (req, res) => {
  const html = `
    <a href="login/vgr">VGR</a><br>
    <a href="login/google">Google</a><br>
    <a href="login/microsoft">Microsoft</a>
  `
  res.send(html)
})


setupFederations().then(() => {
  app.listen(process.env.PORT, () => console.log(`Server started on port: ${process.env.PORT}`))
})



function setupFederations() {
  return Promise.all([
    setupVGRFederation(),
    setupGoogleFederation(),
    setupMicrosoftFederation()
  ])
}

function setupVGRFederation() {
  Issuer.discover(process.env.VGR_DISCOVERY_URI).then(function(issuer) {
    const client = new issuer.Client({
      client_id: process.env.VGR_CLIENT_ID,
      redirect_uris: [process.env.VGR_REDIRECT_URL],
      response_types: ['id_token'],
    })
    const params = {
      resource: 'medlo-local',
      scope: 'openid',
      response_mode: 'form_post',
    }

    passport.use('vgr', new Strategy({client, params}, (tokenset, user, done) => {
      console.log('Response from ADFS:', tokenset, user)
      const accessTokenData = jwtDecode(tokenset.access_token)
      const idTokenData = jwtDecode(tokenset.id_token)
      return done(null, {...user, accessTokenData, idTokenData})
    }))
  })
}

function setupMicrosoftFederation() {
  Issuer.discover(process.env.MICROSOFT_DISCOVERY_URI).then(function(issuer) {
    const client = new issuer.Client({
      client_id: process.env.MICROSOFT_CLIENT_ID,
      client_secret: process.env.MICROSOFT_CLIENT_SECRET,
      redirect_uris: [process.env.MICROSOFT_REDIRECT_URL],
      response_types: ['code']
    })
    const params = {scope: process.env.MICROSOFT_SCOPES}
    passport.use('microsoft', new Strategy({client, params}, (tokenset, user, done) => {
      console.log('Response from microsoft:', tokenset, user)
      return done(null, user)
    }))
  })
}


function setupGoogleFederation() {
  Issuer.discover(process.env.GOOGLE_DISCOVERY_URI).then(function(issuer) {
    const client = new issuer.Client({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uris: [process.env.GOOGLE_REDIRECT_URL],
      response_types: ['code']
    })
    const params = {scope: process.env.GOOGLE_SCOPES}
    passport.use('google', new Strategy({client, params}, (tokenset, user, done) => {
      console.log('Response from google:', tokenset, user)
      return done(null, user)
    }))
  })
}


