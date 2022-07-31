//Imports

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


//ENV
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

//Models
const User = require('./models/User');

//Api
const app = express();
app.use(express.json());

mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.tcfnt.mongodb.net/?retryWrites=true&w=majority`
)


app.get('/', (req, res) => {

    res.status(200).json(
        {
            success: 'true',
            message: 'Bem vindo a API!'
        }
    )
});

function validaToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token){
        return res.status(401).json(
            {
                sucess: "false",
                message: "Acesso negado."
            }
        );
    }

    try{

        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    } catch(e){

        console.error(e);
        return res.status(400).json(
            {
                sucess: "false",
                message: "Token de acesso inválido."
            }
        );
    }
}

//REGISTRAR USUARIO
app.post('/auth/register', async (req, res) => {

    const {name, email, password, confirmPassword} = req.body;

    if(!name || name.toString().length < 6)
        return res.status(422).json({success: 'false', message: 'O username precisa ter pelo menos 6 caracteres.'});

    if(!email || !email.toString().includes('@') || !email.toString().includes('.'))
        return res.status(422).json({success: 'false', message: 'Insira um email válido.'});

    if(!password && !confirmPassword || password != confirmPassword || password.toString().length < 6 )
        return res.status(422).json({success: 'false', message: 'Sua senha e confirma senha precisam ser iguais e devem ter pelo menos 6 caracters.'});

    //Check if user exists
    const userExists = await User.findOne({email: email});

    if(userExists){
        return res.status(422).json({success: 'false', message: 'Email já está sendo utilizado.'});
    }

    //create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try{

        await user.save();
        res.status(201).json({
            sucess: "true",
            message: "Usuário criado com sucesso."
        })
    } catch(e) {

        console.error(e);
        res.status(500).json({
            sucess: "false",
            message: "Não foi possível cadastrar o usuário. Tente novamente mais tarde."
        })
    }
});


//LOGIN USUARIO
app.post('/auth/login', async (req, res) => {

    const {email, password} = req.body;
    
    if(!email || !email.toString().includes('@') || !email.toString().includes('.'))
        return res.status(422).json({success: 'false', message: 'Email ou senha inválidos.'});

    if(!password || password.toString().length < 6 )
        return res.status(422).json({success: 'false', message: 'Email ou senha inválidos.'});

    //Check if user exists
    const user = await User.findOne({email: email});
    if(!user){
        return res.status(404).json({success: 'false', message: 'Usuário não encontrado.'});
    }

    const checkPassword = await bcrypt.compare(password, user.password);
    if(!checkPassword){
        return res.status(422).json({success: 'false', message: 'Email ou senha inválidos.'});
    }

    try{

        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
                id: user.id,
            },
            secret,
        );

        res.status(200).json({
            sucess: "true",
            message: "Login realizado com sucesso.",
            id: user.id,
            user_name: user.name.toString(),
            user_email: user.email.toString(),
            token
        })
    } catch(e){

        console.error(e);
        res.status(500).json({
            sucess: "false",
            message: "Não foi possível fazer o login. Tente novamente mais tarde."
        })
    }
});

//PRIVATE ROUTE
app.get('/user/:id', validaToken , async (req, res) => {

    // const token = req.headers.authorization;
    const id = req.params.id;

    //Check if user exists
    const user = await User.findById(id, '-password');
    if(!user){
        return res.status(404).json({success: 'false', message: 'Usuário não encontrado.'});
    }

    try{
        res.status(200).json({
            user,
            message: "Rota privada acessada!"
        })

    } catch(e){
        console.error(e);
        res.status(500).json({
            sucess: "false",
            message: "Não foi possível fazer o login. Tente novamente mais tarde."
        })
    }
});

app.listen(3000);