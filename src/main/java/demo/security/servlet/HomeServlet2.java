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
    
    private static final String HTML_DOCUMENT = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Greeting</title>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body>
                <h2>Hello </h2>
            </body>
            </html>""";
            
    /**
     * Creates a safe HTML document with the given name.
     * @param name The sanitized name to include
     * @return The complete HTML document
     */
    private static String createHtmlResponse(String name) {
        int insertPoint = HTML_DOCUMENT.indexOf("</h2>");
        if (insertPoint == -1) {
            return HTML_DOCUMENT;
        }
        return HTML_DOCUMENT.substring(0, insertPoint) + name + HTML_DOCUMENT.substring(insertPoint);
    }
            
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
            out.print(createHtmlResponse(sanitizedName));
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
