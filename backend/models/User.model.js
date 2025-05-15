import mongoose from "mongoose";
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    verifyOTP: {
        type: String,
        default: ""
    },
    verifyOTPExpireAt: {
        type: Number,
        default: 0
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    resetOTP: {
        type: String,
        default: ""
    },
    resetOTPExpireAt: {
        type: Number,
        default: 0
    }
}, { timestamps: true });

const userModel = mongoose.model('User', userSchema);
export default userModel;