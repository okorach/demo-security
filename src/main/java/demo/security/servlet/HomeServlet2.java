package demo.security.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

@WebServlet("/helloWorld")
public class HomeServlet2 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    public HomeServlet2() {
        super();
    }


    @Override
    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response) throws ServletException, IOException {
        String name = request.getParameter("name");
        if (name == null) {
            name = "World";
        } else {
            name = name.trim();
        }
        response.setContentType("text/html");
        try (PrintWriter out = response.getWriter()) {
            out.print("<h2>Hello " + Encode.forHtml(name) + "</h2>");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

}
