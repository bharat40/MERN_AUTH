import mongoose from "mongoose";
const connectDatabase = async () => {
    try {
        const response = await mongoose.connect(process.env.MONGODB_URL);
    } catch (error) {
        console.error(error)
    }
}

export default connectDatabase;