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

    private void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

//------------------------------------LOGIN
    public void handleLogin(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }
        if (!"POST".equals(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        try {
            // 1. EXTRAÇÃO: Use exchange.getRequestBody() para ler os bytes do JSON enviado.
            InputStream is = exchange.getRequestBody();

            // 2. CONVERSÃO: Transforme esse JSON em um objeto (ex: LoginRequest) usando Jackson.
            Map<String, String> body = mapper.readValue(is, Map.class);

            String email = body.get("email");
            String password = body.get("password");

            // Validação extra pra evitar erro
            if (email == null || password == null) {
                String response = "{\"error\":\"JSON inválido\"}";
                addCorsHeaders(exchange);
                byte[] bytes = response.getBytes("UTF-8");
                exchange.sendResponseHeaders(400, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }

            // 3. BUSCA E SEGURANÇA:
            //    a) Busque o usuário no 'repository' pelo e-mail fornecido.
            Optional<Usuario> userOpt = repository.findByEmail(email);

            //    b) Se existir, use BCrypt.checkpw(senhaInformada, senhaDoArquivo) para validar.
            if (userOpt.isEmpty() ||
                    !BCrypt.checkpw(password, userOpt.get().getSenhaHash())) {

                // 4. REGRA DE OURO DA SEGURANÇA:
                //    - NUNCA use .equals() ou == para comparar senhas. O BCrypt é a sugestão.
                //    - Em caso de falha, retorne uma mensagem GENÉRICA
                String response = "{\"error\":\"E-mail ou senha inválidos\"}";
                addCorsHeaders(exchange);
                byte[] bytes = response.getBytes("UTF-8");
                exchange.sendResponseHeaders(401, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }

            // 5. RESPOSTA:
            //    - Se as credenciais estiverem OK: Gere o Token via jwtService e retorne 200 OK.
            String token = jwtService.generateToken(userOpt.get());

            String response = "{\"token\":\"" + token + "\"}";
            addCorsHeaders(exchange);
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();

        } catch (Exception e) {
            e.printStackTrace();
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(500, -1);
        }
    }


//--------------------------------------------------REGISTRO


    public void handleRegister(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }
        if (!"POST".equals(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
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
            String password = body.get("password");
            String name = body.get("name"); // opcional

            if (email == null || password == null) {
                String response = "{\"error\":\"JSON inválido\"}";
                addCorsHeaders(exchange);
                byte[] bytes = response.getBytes("UTF-8");
                exchange.sendResponseHeaders(400, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }

            Optional<Usuario> existingUser = repository.findByEmail(email);

            if (existingUser.isPresent()) {
                String response = "{\"error\":\"E-mail já cadastrado\"}";
                addCorsHeaders(exchange);
                byte[] bytes = response.getBytes("UTF-8");
                exchange.sendResponseHeaders(400, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }

            // 2. CRIPTOGRAFIA (Hashing):
            //    A senha recebida NUNCA deve chegar ao arquivo em texto claro.
            //    Gere o hash: BCrypt.hashpw(senhaPura, BCrypt.gensalt(12)).
            //    O "salt" (fator 12) protege contra ataques de Rainbow Tables.

            String senhaHash = BCrypt.hashpw(password, BCrypt.gensalt(12));

            // 3. PERSISTÊNCIA:
            //    Crie uma nova instância de Usuario (model) com a senha já HASHEADA.
            //    Use o repository.save(novoUsuario) para gravar no arquivo JSON.

            Usuario novoUsuario = new Usuario(
                    name != null ? name : email, // fallback se não vier nome
                    email,
                    senhaHash,
                    "USER"
            );

            repository.save(novoUsuario);

            // 4. RESPOSTA: Se tudo der certo, retorne 201 Created.
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(201, -1);

        } catch (Exception e) {
            e.printStackTrace();
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(500, -1);
        }
    }

//--------------------------------------------------DASHBOARD
    public void handleDashboard(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }
        if (!"GET".equals(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        
        
        try {
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");

            // Validacao do token
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {   
                String response = "{\"error\":\"Token ausente ou inválido\"}";
                addCorsHeaders(exchange);
                byte[] bytes = response.getBytes("UTF-8");
                exchange.sendResponseHeaders(401, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }

            // Extracao do token
            String token = authHeader.substring(7); // Removendo o bearer
            if (!jwtService.validateToken(token)) {
                String response = "{\"error\":\"Token invalido ou expirado\"}";
                addCorsHeaders(exchange);
                byte[] bytes = response.getBytes("UTF-8");
                exchange.sendResponseHeaders(401, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }

            String email = jwtService.extractEmail(token); // Extraindo email do token
            String response = "{\"message\":\"Bem-vindo ao dashboard, " + email + "!\"}";
            addCorsHeaders(exchange);
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
            return;

        } catch (Exception e) {
            e.printStackTrace();
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(500, -1);
        }
        
    }
}