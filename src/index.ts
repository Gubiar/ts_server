// index.ts
import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { getRoot, validateToken, getUser, loginUser, registerUser } from './controllers/userController';

dotenv.config();

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI as string);

app.get("/", getRoot);
app.post("/auth/login", loginUser);
app.post("/auth/register", registerUser);
app.get("/user/:id", validateToken, getUser);

const port = 3000;
app.listen(port, () => {
    console.log(`Server iniciado na porta ${port}`)
});
