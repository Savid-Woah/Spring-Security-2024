package springsecurity.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import springsecurity.security.user.User;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "4O3S5aGManXZIaOqUBReq3P4LcPn0wY4L5PxAwoE5ah2npTRz9j6UY7Wy6nXwcDdDW3d";

    private Key getSigningKey(){

        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims extractAllClaims(String token){

        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date extractExpiration(String token){

        return extractClaim(token, Claims::getExpiration);
    }

    public String extractUsername(String token){

        return (String) Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("uuid");
    }

    public String generateToken(Map<String, Object> extraClaims, String subject){

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(User user){

        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("uuid", user.getUuid());
        extraClaims.put("role", user.getRole());
        String subject = "Access_Token";

        return generateToken(extraClaims, subject);
    }

    private boolean isTokenExpired(String token){

        return extractExpiration(token).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails){

        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
}