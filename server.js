const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')

const server = jsonServer.create()
const router = jsonServer.router('./database.json')
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'))

server.use(bodyParser.urlencoded({extended: true}))
server.use(bodyParser.json())
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789'

const expiresIn = '1h'

// Create a token from a payload 
function createToken(payload){
  return jwt.sign(payload, SECRET_KEY, {expiresIn})
}

// Verify the token 
function verifyToken(token){
  return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err)
}

// Check if the user exists in database

function isAuthenticated({loginEmail, loginPassword}){

  return userdb.users.findIndex(user => user.email === loginEmail && user.password === loginPassword) !== -1
}

// Register New User
server.post('/auth/register', (req, res) => {
  console.log("register endpoint called; request body:");

  const {
    registerEmail,
    registerPassword,
    registerFullName,
    registerDate,
    registerPhone,
    registerGender,
    orders
  } = req.body;

  if(isAuthenticated({loginEmail: registerEmail, loginPassword:registerPassword}) === true) {
    const status = 401;
    const message = 'Email and Password already exist';
    res.status(status).json({status, message});
    return
  }

fs.readFile("./users.json", (err, data) => {  
    if (err) {
      const status = 401
      const message = err
      res.status(status).json({status, message})
      return
    };

    // Get current users data
    var data = JSON.parse(data.toString());
  // Get the id of last user
    var last_item_id = data.users[data.users.length-1].id;

    //Add new user
    data.users.push({
      id: last_item_id + 1,
      email: registerEmail,
      password: registerPassword,
      fullName: registerFullName,
      date: registerDate,
      phone: registerPhone,
      gender: registerGender,
      orders:orders
    }); //add some data
    var writeData = fs.writeFile("./users.json", JSON.stringify(data), (err, result) => {  // WRITE
        if (err) {
          const status = 401
          const message = err
          res.status(status).json({status, message})
          return
        }
    });
});

// Create token for new user
  const access_token = createToken({
    registerEmail,
    registerPassword,
    registerFullName,
    registerDate,
    registerPhone,
    registerGender,
    orders
  })
  console.log("Access Token:" + access_token);
  res.status(200).json({access_token})
})

// Login to one of the users from ./users.json
server.post('/auth/login', (req, res) => {
  console.log("login endpoint called; request body:");

  const {loginEmail, loginPassword} = req.body;

  if (isAuthenticated({loginEmail, loginPassword}) === false) {

    const status = 401
    const message = 'Incorrect email or password'
    res.status(status).json({status, message})
    return
  }

  fs.readFile('./users.json', (err, data) => {

    if (err) throw err;
    let json = JSON.parse(data);
    let currentUser = null;
    json.users.forEach((user)=>{
      if (user.email === loginEmail && user.password === loginPassword){
        currentUser = user
      }
    })

    const access_token = createToken(currentUser)

    res.status(200).json({access_token, user:currentUser})
  });

})

server.put('/auth/change-password', (req, res)=>{

  const {editProfileCurrentPassword, editProfileNewPassword, loginEmail, loginPassword} = req.body;

  if (isAuthenticated({loginEmail, loginPassword}) === false) {
    const status = 401
    const message = 'Incorrect email or password'
    res.status(status).json({status, message})
    return
  }

  fs.readFile('./users.json',  (err, data)=>{
    if (err) throw err;
    let json = JSON.parse(data);
    let currentUser = null;

    json.users.forEach((user)=>{
      if (user.password === editProfileCurrentPassword && user.email === loginEmail){
        user.password = editProfileNewPassword
        currentUser = user
        json.users.splice(json.users.indexOf(user), 1, currentUser);
      }
    })

    const access_token = createToken(currentUser)

    fs.writeFile('./users.json', JSON.stringify(json), (err)=>{
          if (err){
            console.log(err)
          }
        })

    res.status(200).json({access_token, user:currentUser})
  });
})


server.put('/auth/edit-profile', (req, res)=>{

  const {editProfileDate, editProfileEmail, editProfileFullName, editProfileGender, editProfilePhone, loginEmail, loginPassword} = req.body;

  if (isAuthenticated({loginEmail, loginPassword}) === false) {
    const status = 401
    const message = 'Incorrect email or password'
    res.status(status).json({status, message})
    return
  }

  fs.readFile('./users.json',  (err, data)=>{
    if (err) throw err;
    let json = JSON.parse(data);
    let currentUser = null;

    json.users.forEach((user)=>{
      if (user.password === loginPassword && user.email === loginEmail){
        user.fullName = editProfileFullName
        user.phone = editProfilePhone
        user.gender = editProfileGender
        user.email = editProfileEmail
        user.date = editProfileDate
        currentUser = user
        json.users.splice(json.users.indexOf(user), 1, currentUser);
      }
    })

    const access_token = createToken(currentUser)

    fs.writeFile('./users.json', JSON.stringify(json), (err)=>{
      if (err){
        console.log(err)
      }
    })

    res.status(200).json({access_token, user:currentUser})
  });
})




server.use(/^(?!\/auth).*$/,  (req, res, next) => {

  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401
    const message = 'Error in authorization format'
    res.status(status).json({status, message})
    return
  }
  try {
    let verifyTokenResult;
     verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

     if (verifyTokenResult instanceof Error) {
       const status = 401
       const message = 'Access token not provided'
       res.status(status).json({status, message})
       return
     }
     next()
  } catch (err) {
    const status = 401
    const message = 'Error access_token is revoked'
    res.status(status).json({status, message})
  }
})

server.use(router)

server.listen(8000, () => {
  console.log('Run Auth API Server')
})