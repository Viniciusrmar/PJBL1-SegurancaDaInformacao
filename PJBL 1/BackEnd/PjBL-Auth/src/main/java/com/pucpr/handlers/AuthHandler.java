package com.pucpr.handlers;

import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Optional;

/**
 * Classe responsável por gerenciar as requisições de Autenticação.
 * Aqui o aluno aprenderá a manipular o corpo de requisições HTTP e
 * aplicar conceitos de hashing e proteção de dados.
 */
public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }


//------------------------------------LOGIN
    public void handleLogin(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            // 1. EXTRAÇÃO: Use exchange.getRequestBody() para ler os bytes do JSON enviado.
            InputStream is = exchange.getRequestBody();

            // 2. CONVERSÃO: Transforme esse JSON em um objeto (ex: LoginRequest) usando Jackson.
            Map<String, String> body = mapper.readValue(is, Map.class);

            String email = body.get("email");
            String senha = body.get("senha");

            // Validação extra pra evitar erro
            if (email == null || senha == null) {
                String response = "{\"error\":\"JSON inválido\"}";
                exchange.sendResponseHeaders(400, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.close();
                return;
            }

            // 3. BUSCA E SEGURANÇA:
            //    a) Busque o usuário no 'repository' pelo e-mail fornecido.
            Optional<Usuario> userOpt = repository.findByEmail(email);

            //    b) Se existir, use BCrypt.checkpw(senhaInformada, senhaDoArquivo) para validar.
            if (userOpt.isEmpty() ||
                    !BCrypt.checkpw(senha, userOpt.get().getSenhaHash())) {

                // 4. REGRA DE OURO DA SEGURANÇA:
                //    - NUNCA use .equals() ou == para comparar senhas. O BCrypt é a sugestão.
                //    - Em caso de falha, retorne uma mensagem GENÉRICA
                String response = "{\"error\":\"E-mail ou senha inválidos\"}";
                exchange.sendResponseHeaders(401, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.close();
                return;
            }

            // 5. RESPOSTA:
            //    - Se as credenciais estiverem OK: Gere o Token via jwtService e retorne 200 OK.
            String token = jwtService.generateToken(userOpt.get());

            String response = "{\"token\":\"" + token + "\"}";
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();

        } catch (Exception e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
        }
    }


//--------------------------------------------------REGISTRO


    public void handleRegister(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            // TODO: O ALUNO DEVE IMPLEMENTAR OS SEGUINTES PASSOS:

            // 1. VALIDAÇÃO DE EXISTÊNCIA:
            //    Antes de cadastrar, verifique se o e-mail já está em uso no 'repository'.
            //    Se já existir, interrompa e retorne 400 Bad Request.

            InputStream is = exchange.getRequestBody();
            Map<String, String> body = mapper.readValue(is, Map.class);

            String email = body.get("email");
            String senha = body.get("senha");
            String nome = body.get("nome"); // opcional

            if (email == null || senha == null) {
                String response = "{\"error\":\"JSON inválido\"}";
                exchange.sendResponseHeaders(400, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.close();
                return;
            }

            Optional<Usuario> existingUser = repository.findByEmail(email);

            if (existingUser.isPresent()) {
                String response = "{\"error\":\"E-mail já cadastrado\"}";
                exchange.sendResponseHeaders(400, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.close();
                return;
            }

            // 2. CRIPTOGRAFIA (Hashing):
            //    A senha recebida NUNCA deve chegar ao arquivo em texto claro.
            //    Gere o hash: BCrypt.hashpw(senhaPura, BCrypt.gensalt(12)).
            //    O "salt" (fator 12) protege contra ataques de Rainbow Tables.

            String senhaHash = BCrypt.hashpw(senha, BCrypt.gensalt(12));

            // 3. PERSISTÊNCIA:
            //    Crie uma nova instância de Usuario (model) com a senha já HASHEADA.
            //    Use o repository.save(novoUsuario) para gravar no arquivo JSON.

            Usuario novoUsuario = new Usuario(
                    nome != null ? nome : email, // fallback se não vier nome
                    email,
                    senhaHash,
                    "USER"
            );

            repository.save(novoUsuario);

            // 4. RESPOSTA: Se tudo der certo, retorne 201 Created.

            exchange.sendResponseHeaders(201, -1);

        } catch (Exception e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
        }
    }
}