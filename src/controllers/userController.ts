// userController.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User, { UserTypes } from '../models/User';
import bcrypt from 'bcrypt';

export const getRoot = (req: Request, res: Response) => {
    res.status(200).json({
        success: "true",
        message: "Bem vindo a API!",
    });
};

export const validateToken = (req: Request, res: Response, next: NextFunction) => {
    const token = req.get('Authorization');
    console.log(token)
    if (!token) {
        return res.status(401).json({
            success: "false",
            message: "Acesso negado.",
        });
    }

    try {
        const secret = process.env.SECRET as string;
        jwt.verify(token, secret);
        next();
    } catch (e) {
        console.error(e);
        return res.status(400).json({
            success: "false",
            message: "Token de acesso inválido.",
        });
    }
};

export const registerUser = async (req: Request, res: Response) => {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || name.toString().length < 6)
        return res.status(422).json({ success: 'false', message: 'O username precisa ter pelo menos 6 caracteres.' });

    if (!email || !email.toString().includes('@') || !email.toString().includes('.'))
        return res.status(422).json({ success: 'false', message: 'Insira um email válido.' });

    if (!password && !confirmPassword || password != confirmPassword || password.toString().length < 6)
        return res.status(422).json({ success: 'false', message: 'Sua senha e confirma senha precisam ser iguais e devem ter pelo menos 6 caracters.' });

    // Check if user exists
    const userExists = await User.findOne({ email: email });

    if (userExists) {
        return res.status(422).json({ success: 'false', message: 'Email já está sendo utilizado.' });
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    }) as UserTypes;

    try {
        await user.save();
        res.status(201).json({
            success: "true",
            message: "Usuário criado com sucesso."
        })
    } catch (e) {
        console.error(e);
        res.status(500).json({
            success: "false",
            message: "Não foi possível cadastrar o usuário. Tente novamente mais tarde."
        })
    }
};

export const loginUser = async (req: Request, res: Response) => {
    const { email, password } = req.body;

    if (!email || !email.toString().includes('@') || !email.toString().includes('.'))
        return res.status(422).json({ success: 'false', message: 'Email ou senha inválidos.' });

    if (!password || password.toString().length < 6)
        return res.status(422).json({ success: 'false', message: 'Email ou senha inválidos.' });

    // Check if user exists
    const user = await User.findOne({ email: email }) as UserTypes;
    if (!user) {
        return res.status(404).json({ success: 'false', message: 'Usuário não encontrado.' });
    }

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        return res.status(422).json({ success: 'false', message: 'Email ou senha inválidos.' });
    }

    try {
        const secret = process.env.SECRET as string;
        const token = jwt.sign(
            {
                id: user.id,
            },
            secret,
        );

        res.status(200).json({
            success: "true",
            message: "Login realizado com sucesso.",
            id: user.id,
            user_name: user.name.toString(),
            user_email: user.email.toString(),
            token
        })
    } catch (e) {
        console.error(e);
        res.status(500).json({
            success: "false",
            message: "Não foi possível fazer o login. Tente novamente mais tarde."
        })
    }
};


export const getUser = async (req: Request, res: Response) => {
    const id = req.params.id;

    // Check if user exists
    const user = await User.findById(id, ["-password", "-name"]);
    if (!user) {
        return res.status(404).json({ success: "false", message: "Usuário não encontrado." });
    }

    try {
        res.status(200).json({
            user,
            message: "Rota privada acessada!",
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({
            success: "false",
            message: "Não foi possível fazer o login. Tente novamente mais tarde.",
        });
    }
};
