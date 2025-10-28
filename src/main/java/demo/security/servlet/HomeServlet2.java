package demo.security.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

/**
 * Servlet implementation class HomeServlet2 for secure greeting functionality.
 */
@WebServlet("/helloWorld")
public class HomeServlet2 extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_NAME = "World";
    private static final int MAX_NAME_LENGTH = 50;
    
    private static final String HTML_TEMPLATE = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Greeting</title>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            </head>
            <body>
                <h2>Hello %s</h2>
            </body>
            </html>""";
            
    /**
     * Sanitizes and validates the user input.
     * @param input The user input to sanitize
     * @return The sanitized input
     */
    private String sanitizeInput(String input) {
        if (input == null || input.trim().isEmpty()) {
            return DEFAULT_NAME;
        }
        String sanitized = input.trim();
        if (sanitized.length() > MAX_NAME_LENGTH) {
            sanitized = sanitized.substring(0, MAX_NAME_LENGTH);
        }
        return Encode.forHtml(sanitized);
    }

    public HomeServlet2() {
        super();
    }


    /**
     * Handles GET requests by displaying a personalized greeting.
     * Implements security measures including input validation and output encoding.
     *
     * @param request The HTTP request
     * @param response The HTTP response
     * @throws ServletException If a servlet-specific error occurs
     * @throws IOException If an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response) throws ServletException, IOException {
        // Set security headers
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("Content-Security-Policy", 
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'");
        
        // Get and sanitize the input
        String sanitizedName = sanitizeInput(request.getParameter("name"));
        
        // Set content type and write response
        response.setContentType("text/html; charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {
            out.print(String.format(HTML_TEMPLATE, sanitizedName));
        }
    }

    /**
     * Handles POST requests by delegating to doGet.
     *
     * @param request The HTTP request
     * @param response The HTTP response
     * @throws ServletException If a servlet-specific error occurs
     * @throws IOException If an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

}
