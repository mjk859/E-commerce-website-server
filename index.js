import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import * as dotenv from 'dotenv';
import UserRouter from './routes/User.js';
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));

//error handler
app.use((err, req, res, next) => {
    const status = err.status || 500;
    const message = err.message || "Something went wrong";
    return res.status(status).json({
        success: false,
        status,
        message,
    })
})

app.get("/", async (req, res) => {
    res.status(200).json({
        message: "OK",
    });
});

app.use("/api/user/", UserRouter);

const connectDB = () => {
    mongoose.set("strictQuery", true);
    mongoose.connect(process.env.MODNO_DB).then(() => console.log("Connected to Mongo DB")).catch((err) => {
        console.error("Error connecting to Mongo");
        console.error(err);
    });
};

const startServer = async () => {
    try {
        connectDB();
        app.listen(8080, () => console.log("Server started on port 8080"))
    } catch (error) {
        console.log(error);
    }
}

startServer();