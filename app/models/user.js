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

userSchema.pre("save",passwordCallback());
userSchema.pre("save",refreshTokenCallback());
userSchema.methods.comparePassword = function(candidatePassword,isPassword,cb){
    var valueToCompare = isPassword? this.password : this.refresh_token;
    bcrypt.compare(candidatePassword,valueToCompare,function(err,isMatch){
        if (err) {return cb(err);}
        cb(null,isMatch);
    });
};
userSchema.methods.generateHashAndSalt = function(valueToHash,req,user,token,next){
    generateHash(valueToHash,next,function(hash){
        user.update({$set:{refresh_token:hash}},function(err){
            if (err) {throw next(err);};
            req.token = token;
            req.refresh_token = valueToHash;
            next();
        });   
    })
}
function passwordCallback(){
    return function(next){
        var user = this;
        if (!user.isModified("password")) {return next();}
        generateHash(user.password,next,function(hash){
            user.password = hash;
            next();
        })
    }
}
function refreshTokenCallback(){
    return function(next){
        var user = this;
        if (!user.isModified("refresh_token")) {return next();}
        generateHash(user.refresh_token,next,function(hash){
            user.refresh_token = hash;
            next();
        })
    }
}
function generateHash(valueToHash,next,cb){
    bcrypt.hash(valueToHash,8,generateHashCallback(next,cb));
}
function generateHashCallback(next,cb){
    return function(err,hash){
        if (err) {throw next(err)};
        cb(hash);
    }
}
module.exports = mongoose.model("User", userSchema);