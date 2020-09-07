const path = require('path');
const express = require('express');
const app = express();
const crypto = require('crypto'); 
const session = require ('express-session'); 
const bodyParser = require('body-parser');
app.use(bodyParser.json());

const Datastore = require('nedb');
var users = new Datastore({ filename: 'db/users.db', autoload: true });
var messages = new Datastore({ filename: path.join(__dirname,'db', 'messages.db'), autoload: true, timestampData : true});
var Message = function item(content, username){
        this.content = content;
        this.username = username;
        this.upvote = 0;
        this.downvote = 0;
}

let isAuthenticated = function(req, res, next) {
    if (!req.username) return res.status(401).end("access denied");
    next();
};

app.use(session({
    secret: 'please change this secret',
    resave: false,
    saveUninitialized: true,
}));
const cookie = require('cookie');

app.use(express.static('static'));

app.use(function (req, res, next){
    var cookies = cookie.parse(req.headers.cookie || '');
    req.username = (cookies.username)? cookies.username : null;
    console.log("HTTP request", req.username, req.method, req.url, req.body);
    next();
});

// curl -H "Content-Type: application/json" -X POST -d '{"username":"alice","password":"alice"}' -c cookie.txt localhost:3000/signup/
app.post('/signup/', function (req, res, next) {
    var username = req.body.username;
    var password = req.body.password;
    var salt = crypto.randomBytes(16).toString('base64');
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var saltedHash = hash.digest('base64');
    console.log(salt, saltedHash);
    users.findOne({_id: username}, function(err, user){
        if (err) return res.status(500).end(err);
        if (user) return res.status(409).end("username " + username + " already exists");
        users.update({_id: username},{_id: username,password:saltedHash,salt}, {upsert: true}, function(err){
            if (err) return res.status(500).end(err);
            // initialize cookie
            res.setHeader('Set-Cookie', cookie.serialize('username', username, {
                  path : '/', 
                  maxAge: 60 * 60 * 24 * 7
            }));
            return res.json("user " + username + " signed up");
        });
    });
});

// curl -H "Content-Type: application/json" -X POST -d '{"username":"alice","password":"alice"}' -c cookie.txt localhost:3000/signin/
app.post('/signin/', function (req, res, next) {
    var username = req.body.username;
   var password = req.body.password;
    // retrieve user from the databasives the user's credentials and compares the password with the one stored in the database.e
    users.findOne({_id: username}, function(err, user){
        if (err) return res.status(500).end(err);
        if (!user) return res.status(401).end("access denied"); 
        var hash = crypto.createHmac('sha512', user.salt);
        hash.update(password);
	console.log(user.password);
        var saltedHash = hash.digest('base64');
	console.log(saltedHash) 
        if (user.password !== saltedHash) return res.status(401).end("access denied"); 
        // initialize cookie
        req.session.username = username; 
        res.setHeader('Set-Cookie', cookie.serialize('username', username, {
              path : '/', 
              maxAge: 60 * 60 * 24 * 7
        }));
        return res.json("user " + username + " signed in");
    });
});

// curl -b cookie.txt -c cookie.txt localhost:3000/signout/
app.get('/signout/', function (req, res, next) {
    req.session.destroy(); 
    res.setHeader('Set-Cookie', cookie.serialize('username', '', {
          path : '/', 
          maxAge: 60 * 60 * 24 * 7 // 1 week in number of seconds
    }));
    res.redirect('/');
});

// curl -b cookie.txt -H "Content-Type: application/json" -X POST -d '{"content":"hello world!"}' localhost:3000/api/messages/
app.post('/api/messages/',isAuthenticated, function (req, res, next) {
    var message = new Message(req.body.content, req.username);
    messages.insert(message, function (err, message) {
        if (err) return res.status(500).end(err);
        return res.json(message);
    });
});

// curl -b cookie.txt localhost:3000/api/messages/
app.get('/api/messages/', function (req, res, next) {
    messages.find({}).sort({createdAt:-1}).limit(5).exec(function(err, messages) { 
        if (err) return res.status(500).end(err);
        return res.json(messages.reverse());
    });
});

// curl -b cookie.txt -H "Content-Type: application/json" -X PATCH -d '{"action":"upvote"}' localhost:3000/api/messages/a66mKb0o3pnnYig4/
app.patch('/api/messages/:id/', isAuthenticated , function (req, res, next) {
    if (['upvote','downvote'].indexOf(req.body.action) == -1) return res.status(400).end("unknown action" + req.body.action);
    messages.findOne({_id: req.params.id}, function(err, message){
        if (err) return res.status(500).end(err);
        if (!message) return res.status(404).end("Message id #" + req.params.id + " does not exists");
        if (message.username !== req.username) return res.status(403).end("forbidden"); 
	var update = {};
        message[req.body.action] += 1;
        update[req.body.action] = 1;
        messages.update({ _id: message._id }, {$inc: update}, { multi: false }, function(err, num) {  
            res.json(message);
         });
    }); 
});

// curl -b cookie.txt -X DELETE localhost:3000/api/messages/a66mKb0o3pnnYig4/
app.delete('/api/messages/:id/', isAuthenticated , function (req, res, next) {
    messages.findOne({_id: req.params.id}, function(err, message){
        if (err) return res.status(500).end(err);
        if (!message) return res.status(404).end("Message id #" + req.params.id + " does not exists");
        if (message.username !== req.username) return res.status(403).end("forbidden");
        messages.remove({ _id: message._id }, { multi: false }, function(err, num) {  
            res.json(message);
         });
    }); 
});
app.get('/private/', isAuthenticated, function (req, res, next) {
    return res.end("This is private");
});
const http = require('http');
const PORT = 3000;

http.createServer(app).listen(PORT, function (err) {
    if (err) console.log(err);
    else console.log("HTTP server on http://localhost:%s", PORT);
});
