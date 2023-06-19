import express  from "express";
import { config } from "dotenv";
import cookieParser from "cookie-parser";
import ErrorMiddelware from "./middelware/error.js";
import userRoute from "./routes/userRoute.js"



const app = express();
app.use(express.json());
app.use(cookieParser());

// Config
config({
    path:"./config/config.env"
})

app.get("/", (req, res)=>{
    res.send("Welcome")
})

// Using Route
app.use("/api/v1", userRoute)



export default app

// Using ErrorMiddelware
app.use(ErrorMiddelware);