# Auth MERN

## Dependencies Used

- bcryptjs
- cookie-parser
- cors
- dotenv
- jsonwebtoken
- express
- nodemon
- mongoose
- nodemailer : Used to send OTPs and password reset emails through a custom or Gmail SMTP server.

## Tools Used

- Brevo : Used to send transactional emails like verification and reset OTPs via Brevo's email API service.

- Postman
- VS Code

## Routes

- route.post('/register', register); // Registers a new user account.

- route.post('/login', login); // Logs in a user with email and password.

- route.post('/logout', logout); // Logs out the currently authenticated user.

- route.post('/send-verification-otp', userAuth, sendEmailVerificationOtp); // Sends an OTP to verify the user's email.

- route.post('/verify-email', userAuth, verifyEmail); // Verifies the user's email using the OTP.

- route.post('/is-authenticated', userAuth, isAuthenticated); // Checks if the user is currently authenticated.

- route.post('/send-password-reset-otp', userAuth, sendResetPasswordOtp); // Sends an OTP to reset the user's password.

- route.post('/reset-password', resetPassword); // Resets the user's password using OTP.

- route.get('/get-user-details', userAuth, getUserDetails); // Retrieves the details of the authenticated user.

## Middleware

- Middleware to verify JWT from cookies and authorize the user by attaching user ID to the request body.
