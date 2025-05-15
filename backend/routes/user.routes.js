import { Router } from 'express';
const route = Router();
import { register, login, logout, verifyEmail, sendEmailVerificationOtp, isAuthenticated, sendResetPasswordOtp, resetPassword, getUserDetails } from '../controllers/user.controller.js';
import userAuth from '../middleware/userAuth.js';


route.post('/register', register);
route.post('/login', login);
route.post('/logout', logout);
route.post('/send-verification-otp', userAuth, sendEmailVerificationOtp);
route.post('/verify-email', userAuth, verifyEmail);
route.post('/is-authenticated', userAuth, isAuthenticated);
route.post('/send-password-reset-otp', userAuth, sendResetPasswordOtp);
route.post('/reset-password', resetPassword);
route.get('/get-user-details', userAuth, getUserDetails);

export default route;