import userModel from "../models/User.model.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import transporter from '../config/nodemailer.js';


const register = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(404).json({
            success: false,
            message: 'Missing Details'
        });
    }
    try {
        const existed_user = await userModel.findOne({ email });
        if (existed_user) {
            return res.status(400).json({ success: false, message: "User Already Exists with this Email Address" });
        }
        const hashed_password = await bcrypt.hash(password, 10);
        const new_user = new userModel({ name: name, email: email, password: hashed_password });
        await new_user.save();
        const token = jwt.sign({ id: new_user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '7d' });
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: `Welcome ${name} to our Website`,
            text: `Welcome to our Website. Your account has been created with Email Address: ${email}`
        }
        await transporter.sendMail(mailOptions);
        return res.status(200).cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }).json({ success: true, message: "Successfully Registered" });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(404).json({
            success: false,
            message: 'Missing Details'
        });
    }

    try {
        const existed_user = await userModel.findOne({ email });
        if (!existed_user) {
            return res.status(404).json({
                success: false,
                message: "User with this Email Address does not exists"
            });
        }
        const isPasswordMatch = await bcrypt.compare(password, existed_user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ success: false, message: "Password is Incorrect" });
        }
        const token = jwt.sign({ id: existed_user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '7d' });
        return res.status(200).cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }).json({ success: true, message: "Successfully Logged In" });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        })
        return res.status(200).json({ success: true, message: "Successfully Logged Out" });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}


const sendEmailVerificationOtp = async (req, res) => {
    try {
        const { id } = req.body;
        const user = await userModel.findById(id);
        if (user.isVerified) {
            return res.status(200).json({ success: false, message: "Account Already Verified" });
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOTP = otp;
        user.verifyOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: `Account Verification OTP`,
            text: `Hi ${user.name}! your OTP is ${otp} to verify your account associated with Email Address ${user.email}. Please Note OTP expires in ${user.verifyOTPExpireAt}`
        }
        await transporter.sendMail(mailOptions);
        return res.status(200).json({ success: true, message: `Verification OTP Sent on Email Address ${user.email}` });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

const verifyEmail = async (req, res) => {
    const { otp, id } = req.body;
    if (!otp || !id) {
        return res.status(404).json({
            success: false,
            message: 'Missing Details'
        });
    }
    try {
        const user = await userModel.findById(id);
        if (user.verifyOTP != otp) {
            return res.status(400).json({ success: false, message: "Wrong OTP Entered" });
        }
        if (user.verifyOTPExpireAt < Date.now()) {
            return res.status(500).json({ sucees: false, message: "OTP Expired" });
        }
        user.isVerified = true;
        user.verifyOTP = "";
        user.verifyOTPExpireAt = 0;
        await user.save();
        return res.status(200).json({ success: true, message: `Email Address ${user.email} Successfully Verified` });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

const isAuthenticated = async (req, res) => {
    try {
        return res.status(200).json({ success: true, message: "Already Logged In" });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

const sendResetPasswordOtp = async (req, res) => {
    try {
        const { id } = req.body;
        const user = await userModel.findById(id);
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOTP = otp;
        user.resetOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Hi ${user.name}! your OTP is ${otp} to reset your password for account associated with Email Address ${user.email}. Please Note OTP expires in ${user.resetOTPExpireAt}`
        }
        await transporter.sendMail(mailOptions);
        return res.status(200).json({ success: true, message: `Password reset OTP sent on Email Address ${user.email}` });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
        return res.status(404).json({ success: false, message: "Missing Details" });
    }
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: `User with Email Address ${email} not found` });
        }
        if (user.resetOTP != otp) {
            return res.status(400).json({ success: false, message: "Wrong OTP Entered" });
        }
        if (user.resetOTPExpireAt < Date.now()) {
            return res.status(500).json({ sucees: false, message: "OTP Expired" });
        }
        const newPasswordHashed = await bcrypt.hash(newPassword, 10);
        user.password = newPasswordHashed;
        user.resetOTP = '';
        user.resetOTPExpireAt = 0;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Successfully Reset',
            text: `Hi ${user.name} your account's password is reset`
        }
        await transporter.sendMail(mailOptions);
        return res.status(200).json({ success: true, message: `Password successfully reset for account associated with Email Address ${user.email}` });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}


const getUserDetails = async (req, res) => {
    try {
        const { id } = req.body;
        const user = await userModel.findById(id);
        return res.status(200).json({ success: true, userData: { name: user.name, email: user.email, isAccountVerified: user.isVerified } })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

export { register, login, logout, sendEmailVerificationOtp, verifyEmail, isAuthenticated, sendResetPasswordOtp, resetPassword, getUserDetails };