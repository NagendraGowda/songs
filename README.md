https://github.com/NagendraGowda/songs/raw/main/Sweethearts%20-%20TrackTribe.mp3
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// User model
class User {
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}

// Authentication Service
class AuthenticationService {
    private static final String SECRET_KEY = "secret";
    private static final long EXPIRATION_TIME = 900_000; // 15 minutes

    public static String generateToken(User user) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
        String token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(algorithm);
        return token;
    }

    public static boolean validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            JWT.require(algorithm).build().verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }
}

// Login Servlet
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Authenticate user (e.g., check credentials against a database)
        User user = new User("admin", "admin"); // Example user
        
        if (user.getUsername().equals(username) && user.getPassword().equals(password)) {
            // Generate JWT token
            String token = AuthenticationService.generateToken(user);
            
            // Return token to client (e.g., as JSON response)
            response.setContentType("application/json");
            response.getWriter().write("{\"token\": \"" + token + "\"}");
        } else {
            // Handle authentication failure
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}

// Example Servlet for accessing a protected resource
@WebServlet("/resource")
public class ResourceServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Check if the request contains a valid token
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7); // Remove "Bearer " prefix
            if (AuthenticationService.validateToken(token)) {
                // Token is valid, return resource
                response.getWriter().write("Welcome to the protected resource!");
                return;
            }
        }
        // Unauthorized access
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}

// Servlet Filter for token validation
@WebFilter("/resource")
public class TokenValidationFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String token = httpRequest.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7); // Remove "Bearer " prefix
            if (AuthenticationService.validateToken(token)) {
                // Token is valid, proceed with the request
                chain.doFilter(request, response);
                return;
            }
        }
        // Unauthorized access
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    // Other methods in the Filter interface (init, destroy) can be left empty
    public void init(FilterConfig filterConfig) throws ServletException {}
    public void destroy() {}
}
