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
        response.setHeader("Content-Security-Policy", "default-src 'self'");
        
        String name = request.getParameter("name");
        if (name == null || name.trim().isEmpty()) {
            name = DEFAULT_NAME;
        } else {
            name = name.trim();
            if (name.length() > MAX_NAME_LENGTH) {
                name = name.substring(0, MAX_NAME_LENGTH);
            }
        }
        
        response.setContentType("text/html; charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {
            StringBuilder html = new StringBuilder()
                .append("<!DOCTYPE html>\n")
                .append("<html>\n")
                .append("<head>\n")
                .append("<title>Greeting</title>\n")
                .append("</head>\n")
                .append("<body>\n")
                .append("<h2>Hello ").append(Encode.forHtml(name)).append("</h2>\n")
                .append("</body>\n")
                .append("</html>");
            out.print(html.toString());
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
