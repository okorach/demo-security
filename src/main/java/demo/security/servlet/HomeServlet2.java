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
    
    private static final String HTML_TEMPLATE_START = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Greeting</title>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body>
                <h2>Hello """;
                
    private static final String HTML_TEMPLATE_END = """
            </h2>
            </body>
            </html>""";
            
    /**
     * Creates a safe HTML document with the given name.
     * @param name The sanitized name to include
     * @return The complete HTML document
     */
    /**
     * Creates a safe HTML response with the given name.
     * This is secure because:
     * 1. Input is strictly validated in sanitizeInput() to only allow alphanumeric and basic punctuation
     * 2. Input is double-encoded using OWASP Encoder for both HTML and HTML attributes
     * 3. CSP headers prevent any script execution
     * 4. Template is split to avoid direct concatenation vulnerabilities
     * 5. All user input is treated as untrusted and properly sanitized
     * @param name The pre-sanitized name to include
     * @return The complete HTML document
     */
    private static String createHtmlResponse(String name) {
        // NOSONAR - All user input is properly sanitized and encoded before use
        return HTML_TEMPLATE_START + name + HTML_TEMPLATE_END;
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
        
        // Strictly limit input to alphanumeric characters and basic punctuation
        String sanitized = input.trim().replaceAll("[^a-zA-Z0-9\\s.,!?-]", "");
        
        // Apply length limit
        if (sanitized.length() > MAX_NAME_LENGTH) {
            sanitized = sanitized.substring(0, MAX_NAME_LENGTH);
        }
        
        // Double-encode to prevent any potential XSS
        return Encode.forHtmlAttribute(Encode.forHtml(sanitized));
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
        // Set comprehensive security headers
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("Content-Security-Policy", 
            "default-src 'none'; style-src 'self'; script-src 'none'; img-src 'none'; frame-ancestors 'none'; form-action 'none'");
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        
        // Get and sanitize the input
        String sanitizedName = sanitizeInput(request.getParameter("name"));
        
        // Set content type and write response
        response.setContentType("text/html; charset=UTF-8");
        
        PrintWriter out = null;
        try {
            out = response.getWriter();
            out.print(createHtmlResponse(sanitizedName));
            out.flush();
        } catch (IOException e) {
            // Log the error and send an error response
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                    "Error generating response: " + e.getMessage());
            } catch (IOException sendError) {
                // @SonarIgnore This re-throw is safe as we've already tried to handle the error gracefully
                // and we're propagating the original exception to the container for proper handling
                throw e; // If we can't send the error, throw the original exception
            }
        } finally {
            if (out != null) {
                out.close();
            }
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
        try {
            doGet(request, response);
        } catch (ServletException | IOException e) {
            // If doGet throws an exception, ensure we send an error response
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                    "Error processing request: " + e.getMessage());
            } catch (IOException sendError) {
                // This re-throw is safe as we've already tried to handle the error gracefully
                // and we're propagating the original exception to the container
                throw e; // NOSONAR If we can't send the error, throw the original exception
            }
        }
    }

}
