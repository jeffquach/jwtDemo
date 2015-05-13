var mongoose = require("mongoose");
var bcrypt = require("bcryptjs");
var Schema = mongoose.Schema;

var userSchema = new Schema({
	name: String,
	password: String,
	admin: Boolean,
	refresh_token: String,
	status: {type: String, default: "active"}
});

userSchema.pre("save",function(next){
	var user = this;
	if (!user.isModified("password")) {return next();}
	if (!user.isModified("refresh_token")) {return next();}
	bcrypt.genSalt(10,function(err,salt){
		if (err) {return next(err);}
		bcrypt.hash(user.password,salt,function(err,hash){
			if (err) {return next(err);}
			user.password = hash;
			next();
		});
	});
	bcrypt.genSalt(10,function(err,salt){
		if (err) {return next(err);}
		bcrypt.hash(user.refresh_token,salt,function(err,hash){
			if (err) {return next(err);}
			user.refresh_token = hash;
			next();
		});
	});
});

userSchema.methods.comparePassword = function(candidatePassword,cb){
	bcrypt.compare(candidatePassword,this.password,function(err,isMatch){
		if (err) {return cb(err);}
		cb(null,isMatch);
	});
};

module.exports = mongoose.model("User", userSchema);