# Projeto Servidor Web em Node.js com Express e TypeScript

Este projeto é uma implementação de um servidor web usando Node.js, Express e TypeScript. O servidor fornece uma API para autenticação de usuários, incluindo registro e login.

## Tecnologias Utilizadas

- **Node.js**: Uma plataforma de tempo de execução JavaScript que permite executar código JavaScript no lado do servidor.
- **Express**: Um framework web para Node.js que simplifica o desenvolvimento de aplicações web.
- **TypeScript**: Um superconjunto tipado de JavaScript que adiciona tipos estáticos ao JavaScript, tornando o código mais fácil de entender e menos propenso a erros.
- **Mongoose**: Uma biblioteca do Node.js que proporciona uma solução direta e baseada em esquemas para modelar os dados da sua aplicação usando MongoDB.
- **bcrypt**: Uma biblioteca para ajudar você a fazer hash das senhas.
- **jsonwebtoken**: Uma implementação de tokens de acesso JSON Web Token.

## Objetivo do Projeto

O objetivo deste projeto é fornecer uma API para autenticação de usuários. A API permite que os usuários se registrem fornecendo um nome, email e senha. Os usuários registrados podem então fazer login usando seu email e senha.

Os endpoints da API incluem:

- `POST /auth/register`: Registra um novo usuário. Espera um corpo de solicitação com `name`, `email`, `password` e `confirmPassword`.
- `POST /auth/login`: Faz login de um usuário existente. Espera um corpo de solicitação com `email` e `password`.
- `GET /user/:id`: Retorna os detalhes do usuário para o ID do usuário fornecido. Este é um endpoint protegido que requer um token JWT válido.

Espero que você ache este projeto útil! Se você tiver alguma dúvida ou sugestão, sinta-se à vontade para contribuir. 😊