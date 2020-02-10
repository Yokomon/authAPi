
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: 'Your email is required',
        trim: true
    },

    name: {
        type: String,
        unique: true,
        required: 'Your username is required',
    },

    password: {
        type: String,
        required: 'Your password is required',
        max: 100
    },

    bio: {
        type: String,
        required: 'Your bio is necessary'
    },

    mobile:{
        type: String,
        required: 'Your mobile number is required',
        max: 14,
    },
    gender: {
        type: String,
        required: 'Please select your gender!'
    },
    logo:{
        type: String,
        required: 'Specify your logo here'
    },
    brandName:{
        type: String,
        required: 'Would you not want the world to know your Brand?'
    },
    priceRange:{
        type: String,
        required: 'What is the price range?'
    },
    profileImage: {
        type: String,
        required: false,
        max: 255
    }
}, {timestamps: true});


UserSchema.pre('save',  function(next) {
    const user = this;

    if (!user.isModified('password')) return next();

    bcrypt.genSalt(10, function(err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, function(err, hash) {
            if (err) return next(err);

            user.password = hash;
            next();
        });
    });
});

UserSchema.methods.comparePassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};

UserSchema.methods.generateJWT = function() {
    const today = new Date();
    const expirationDate = new Date(today);
    expirationDate.setDate(today.getDate() + 60);

    let payload = {
        id: this._id,
        email: this.email,
        name: this.name,
    };

    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: parseInt(expirationDate.getTime() / 1000, 10)
    });
};

mongoose.set('useFindAndModify', false);
module.exports = mongoose.model('Users', UserSchema);