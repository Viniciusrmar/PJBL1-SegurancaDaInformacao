package com.pucpr.service;
import com.pucpr.model.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtService {

    // TODO: O ALUNO DEVE BUSCAR DE UMA VARIÁVEL DE AMBIENTE (System.getenv)

    private SecretKey getSigningKey() {
        String secret = System.getenv("JWT_SECRET");
        return Keys.hmacShaKeyFor(secret.getBytes());
    }


//------------------------------------Geração do Token
    public String generateToken(Usuario user) {
        // Exemplo de implementação que eles podem seguir ou completar
        String secret = System.getenv("JWT_SECRET"); // Ensinar boas práticas!
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("role", user.getRole())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900000)) // 15 min
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()))
                .compact();
    }

    /**
     * Gera o token assinado.
     * 1. Define o 'subject' (e-mail do usuário).
     * 2. Adiciona Claims customizadas (como o 'role').
     * 3. Define a data de emissão e expiração (ex: 15 min).
     * 4. Assina com a chave e o algoritmo HS256.
     */


//------------------------------------

//------------------------------------Extração
    public String extractEmail(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * Extrai o e-mail (subject) do token.
     * TODO: O ALUNO DEVE IMPLEMENTAR:
     * 1. Usar Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).
     * 2. Retornar o Subject do Payload.
     */
//------------------------------------

//------------------------------------Validação do Token
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Valida se o token é autêntico e não expirou.
     * TODO: O ALUNO DEVE IMPLEMENTAR:
     * 1. Tentar fazer o parse do token.
     * 2. Se o parse falhar (assinatura errada ou expirado), a biblioteca joga uma Exception.
     * 3. Retornar true se o token for válido e false caso capture uma exceção.
     */
//------------------------------------

}
