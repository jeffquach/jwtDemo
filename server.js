var express     = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var mongoose    = require('mongoose');
var bcrypt = require("bcrypt");
var fs = require("fs");
var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file
var User   = require('./app/models/user'); // get our mongoose model
var crypto = require('crypto');

var port = process.env.PORT || 3000;
mongoose.connect(config.database);
app.set("superSecret",config.secret);

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// =======================
// routes ================
// =======================
// basic route
app.get('/', function(req, res) {
    res.send('Hello! The API is at http://localhost:' + port + '/api');
});
app.get('/setup', function(req, res) {

  // create a sample user
	var id,darmish;
	crypto.randomBytes(35, function(err, buffer) {
		if (err) throw err;
	  	id = buffer.toString('hex');
	  	//id = "roquan";
	  	darmish = new User({ 
		    name: 'darmish', 
		    password: 'darmish',
		    admin: true,
		    refresh_token:id 
		});
		  // save the sample user
		  darmish.save(function(err) {
		    if (err) throw err;

		    console.log('User saved successfully');
		    res.json({ success: true, uuid: id});
		  });
	});
});

// API ROUTES -------------------
// we'll get to these in a second
var apiRoutes = express.Router();

apiRoutes.post("/authenticate",function(req,res){
	console.log("$$$ req.decoded $$$");
	console.log(req.decoded);
	jwtAuth({name: req.body.name},req.body.password,res,function(token){
		console.log("$$$ token $$$");
		console.log(token);
		if (token) {
			res.json({success:true,message:"Here's your token hater!",token:token});
		}else{
			res.status(401).json({success:false,message:"Wrong password yo!"})
		}
	});
	// User.findOne({name: req.body.name}, function(err,user){
	// 	if (err) {throw err;};
	// 	if (!user) {
	// 		res.json({success:false,message:"Authentication failed, probs a wrong password or somethang!"});
	// 	}else if(user){
	// 		user.comparePassword(req.body.password,function(err,matchingPassword){
	// 			if (!matchingPassword) {
	// 				res.status(401).json({success:false,message:"Wrong password yo!"});
	// 			}else{
	// 				console.log("$$$ User is $$$");
	// 				console.log(user);
	// 				var cert = fs.readFileSync("./private.pem");
	// 				var token = jwt.sign({user:user.name},cert,{algorithm:"RS256",expiresInMinutes:1,ignoreExpiration:false});
	// 				res.json({success:true,message:"Here's your token hater!",token:token});
	// 			}
	// 		})
	// 	}
	// });
});

function jwtAuth(nameOrIdentifier,password,res,callback){
	User.findOne(nameOrIdentifier, function(err,user){
		if (err) {throw err;};
		if (!user) {
			res.json({success:false,message:"Authentication failed, probs a wrong password or somethang!"});
		}else if(user && user.status === "active"){
			console.log("$$$ password $$$:");
			console.log(password);
			user.comparePassword(password,true,function(err,matchingPassword){
				console.log("$$$ matchingPassword $$$");
				console.log(matchingPassword);
				if (!matchingPassword) {
					callback(null);
				}else{
					console.log("$$$ User is $$$");
					console.log(user);
					var cert = fs.readFileSync("./private.pem");
					var token = jwt.sign({user:user.name},cert,{algorithm:"RS256",expiresInMinutes:1,ignoreExpiration:false});
					callback(token);
				}
			})
		}
	});
}

// Place middleware for jwt code above here to get the code to run for these routes that require the webtoken

apiRoutes.use(function(req,res,next){
	var token = req.body.token || req.query.token || req.headers['x-access-token'];
	if (token) {
		var cert = fs.readFileSync("./public.pem");
		//var cert = fs.readFileSync("./jwtPrivateKey.pem");
		jwt.verify(token,cert,{algorithms:["RS256"],ignoreExpiration:false},function(err,decoded){
			if (err) {
				//res.json({message:"Big time problems son!"});
				console.log("$$$ ERROR $$$");
				console.log(err);
				console.log("$$$ decoded (ERROR) object from jwt.verify callback is $$$:");
				console.log(decoded);
				var refresh_token = req.headers['x-refresh-token'];
				console.log("$$$ refresh token $$$");
				console.log(refresh_token);
				console.log("$$ USERNAME $$");
				var username = req.query.username;
				console.log(username);
				if (username) {
					
					User.findOne({name:username},function(err,user){
						console.log("$$$ USER $$$");
						console.log(user);

						bcrypt.compare(refresh_token,user.refresh_token,function(err,matchingPassword){
							console.log("$$$ matchingPassword $$$");
							console.log(matchingPassword);
							if (!matchingPassword) {
								return res.json({message:"Big time problems son!"});
							}else{
								var new_refresh_token,cert = fs.readFileSync("./private.pem");
								var token = jwt.sign({user:user.name},cert,{algorithm:"RS256",expiresInMinutes:1,ignoreExpiration:false});
								crypto.randomBytes(35, function(ex, buffer) {
									if (err) {return next(err);}
								  	new_refresh_token = buffer.toString('hex');
							  		bcrypt.genSalt(10,function(err,salt){
										if (err) {return next(err);}
										bcrypt.hash(new_refresh_token,salt,function(err,hash){
											if (err) {return next(err);}
											user.update({$set:{refresh_token:hash}},function(err){
												if (err) {throw err;};
												req.token = token;
												req.refresh_token = new_refresh_token;
												next();
											});
										});
									});
								});
							}
						});
					
						// user.comparePasswordTingz(refresh_token,function(err,matchingPassword){
						// 	console.log("$$$ matchingPassword $$$");
						// 	console.log(matchingPassword);
						// 	if (!matchingPassword) {
						// 		return res.json({message:"Big time problems son!"});
						// 	}else{
						// 		// console.log("$$$ MATCHES! $$$");
						// 		// next();
						// 		var id,cert = fs.readFileSync("./private.pem");
						// 		var token = jwt.sign({user:user.name},cert,{algorithm:"RS256",expiresInMinutes:1,ignoreExpiration:false});
						// 		crypto.randomBytes(35, function(ex, buf) {
						// 		  	id = buf.toString('hex');
						// 	  		bcrypt.genSalt(10,function(err,salt){
						// 				if (err) {return next(err);}
						// 				bcrypt.hash(refresh_token,salt,function(err,hash){
						// 					if (err) {return next(err);}
						// 					user.update({$set:{refresh_token:hash}},function(err){
						// 						if (err) {throw err;};
						// 						req.token = token;
						// 						req.refresh_token = id;
						// 						next();
						// 					});
						// 				});
						// 			});
						// 		});
						// 	}
						// })
					});
					//next();
				}
				else{
					return res.json({success:false,message:"Failed to authenticate token"});
				}
			}else{
				console.log("$$$ decoded object from jwt.verify callback is $$$:");
				console.log(decoded);
				req.decoded = decoded;
				req.jammers = "Yo bro!";
				next();
			}
		})
	}else{
		return res.status(403).send({
			success: false,
			message: "No token son!"
		});
	}
});

apiRoutes.get("/",function(req,res){
	res.json({message: "Yo hater, diz API be bumpin' son!",jwt: req.token, refresh_token: req.refresh_token});
});

apiRoutes.get("/users",function(req,res){
	User.find({},function(err,users){
		res.json({users:users,jwt: req.token, refresh_token: req.refresh_token});
	});
});
apiRoutes.get("/darmish",function(req,res){
	console.log("$$$ req.query $$$");
	console.log(req.query);
	User.findOne({name:req.query.darmish},function(err,users){
		res.json({user:users});
	});
});

app.use("/api",apiRoutes);
// =======================
// start the server ======
// =======================
app.listen(port);
console.log('Magic happens at http://localhost:' + port);