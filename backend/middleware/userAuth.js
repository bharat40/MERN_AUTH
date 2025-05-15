import jwt from 'jsonwebtoken';
const userAuth = async (req, res, next) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(404).json({ success: false, message: "You are not Authorized, Please Login Again." });
    }
    try {
        const decoded_token = jwt.verify(token, process.env.JWT_SECRET_KEY);
        if (decoded_token.id) {
            req.body = req.body || {};
            req.body.id = decoded_token.id;
        }
        else {
            return res.status(404).json({ success: false, message: "You are not Authorized, Please Login Again." });
        }
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

export default userAuth;