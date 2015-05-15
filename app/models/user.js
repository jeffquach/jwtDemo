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

userSchema.pre("save",hashedValueCallback("password",true));
userSchema.pre("save",hashedValueCallback("refresh_token",false));
function hashedValueCallback(userValue,isPassword){
    return function(next){
    	var user = this;
	    if (!user.isModified(userValue)) {return next();}
	    bcrypt.genSalt(10,saltCallback(user, isPassword, next));
    }
}
function saltCallback(user, isPassword, next){
    return function(err,salt){
    	var valueToHash = isPassword? user.password : user.refresh_token;
        bcrypt.hash(valueToHash,salt,hashCallback(user, isPassword, next));
    }
}
function hashCallback(user, isPassword, next){
    return function(err,hash){
        if (err) {return next(err);}
        if (isPassword) {
        	user.password = hash;
        }else{
        	user.refresh_token = hash;
        }
        next();
    }
}
userSchema.methods.comparePassword = function(candidatePassword,isPassword,cb){
	var valueToCompare = isPassword? this.password : this.refresh_token;
	bcrypt.compare(candidatePassword,valueToCompare,function(err,isMatch){
		if (err) {return cb(err);}
		cb(null,isMatch);
	});
};

module.exports = mongoose.model("User", userSchema);