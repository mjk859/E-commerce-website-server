import User from "../models/User.js";
import {createError} from "../error.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from 'dotenv';

dotenv.config(); 

export const UserRegister = async (req, res, next) => {
    try {
        const { email, password, name, img } = req.body;
        const existingUser = await User.findOne({ email});
        if (existingUser) {
            return next(createError(409, "Email is already in use"))
        }
        // const salt = bcrypt.genSaltSync(10, (err) => {
        //     if (err) throw err;
        // });
        // const hashedPassword = bcrypt.hashSync(password, salt, (err) => {
        //     if (err) throw err;
        // });

        // Minor must be either a or b error is coming so used below code snippet

        const hashedPassword = (password) => {
            var salt = bcrypt.genSalt(10);
            return bcrypt.hash(password, salt);
        }

        const user = new User({
            name,
            email,
            password: hashedPassword,
            img,
        });
        const createduser = user.save();
        const token = jwt.sign({id: createduser._id }, process.env.JWT, {
            expiresIn: "9999 years",
        });
        return res.status(200).json({token, user});
    } catch (err) {
        return next(err);
    }
};