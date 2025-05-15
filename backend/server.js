import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
const app = express();
import connectDatabase from './database/db.js';
const port = process.env.PORT || 4000;
app.use(cors({ credentials: true }));
app.use(express.json());
app.use(cookieParser());
import userRoutes from './routes/user.routes.js';

app.use('/api/auth', userRoutes);

const startServer = async () => {
    try {
        await connectDatabase();
        console.log("MongoDB connected");
        app.listen(port, () => {
            console.log(`Server is running at port:${port}`);
        })
    } catch (error) {
        console.error(error);
    }
}
startServer();