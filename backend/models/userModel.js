

const mongoose = require('mongoose');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        trim: true,
        required: [true, 'firstName is required'],
        maxLength: 32,
    },
    lastName: {
        type: String,
        trim: true,
        required: [true, 'last Name is required'],
        maxLength: 32,
    },
    password: {
        type: String,
        trim: true,
        required: [true, 'password must have at least six characters'],
        minLength: 6,
    },
    role:{
        type: Number,
        default: 0
    },
    email: {
        type: String,
        trim: true,
        required: [true, 'email is required'],
        unique: true,
        match: [
            /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/,
            'please add a valid mail'
        ]
    },
} , {timestamps:true})

//encrypting password before saving
userSchema.pre('save', async function(next){
    if (!this.isModified('password')){
            next();
    }
    this.password = await bcrypt.hash(this.password, 10)
})
// compare user password
userSchema.methods.comparePassword = async function (enteredpassword){
    return await bcrypt.compare(enteredpassword, this.password)
}



//return a jwt token
userSchema.methods.getJwtToken = function (){
    return jwt.sign({id: this.id}, process.env.JWT_SECRET, {
        expiresIn: 3600
    });
}


module.exports = mongoose.model("user", userSchema);