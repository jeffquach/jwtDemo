var mongoose = require("mongoose");
var bcrypt = require("bcrypt");
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
	bcrypt.genSalt(10,function(err,salt){
		if (err) {return next(err);}
		bcrypt.hash(user.password,salt,function(err,hash){
			if (err) {return next(err);}
			user.password = hash;
			next();
		});
	});
});
userSchema.pre("save",function(next){
	var user = this;
	if (!user.isModified("refresh_token")) {return next();}
	bcrypt.genSalt(10,function(err,salt){
		if (err) {return next(err);}
		bcrypt.hash(user.refresh_token,salt,function(err,hash){
			if (err) {return next(err);}
			user.refresh_token = hash;
			next();
		});
	});
});

userSchema.methods.comparePassword = function(candidatePassword,isPassword,cb){
	var valueToCompare = isPassword? this.password : this.refresh_token;
	console.log("$$$ comparePassword $$$");
	console.log(valueToCompare);
	bcrypt.compare(candidatePassword,valueToCompare,function(err,isMatch){
		if (err) {return cb(err);}
		cb(null,isMatch);
	});
};
userSchema.methods.comparePasswordTingz = function(candidatePassword,cb){
	bcrypt.compare(candidatePassword,this.refresh_token,function(err,isMatch){
		if (err) {return cb(err);}
		cb(null,isMatch);
	});
};

module.exports = mongoose.model("User", userSchema);