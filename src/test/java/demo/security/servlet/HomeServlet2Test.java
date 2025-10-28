package demo.security.servlet;

import static org.mockito.Mockito.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;

class HomeServlet2Test {
    private HomeServlet2 servlet;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private StringWriter stringWriter;
    private PrintWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        servlet = new HomeServlet2();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        stringWriter = new StringWriter();
        writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);
    }

    @Test
    void doGet_whenNameParameterIsNull_shouldReturnDefaultGreeting() throws Exception {
        when(request.getParameter("name")).thenReturn(null);
        
        servlet.doGet(request, response);
        writer.flush();
        
        verify(response).setContentType("text/html");
        assert(stringWriter.toString().contains("Hello World"));
    }

    @Test
    void doGet_withValidName_shouldReturnPersonalizedGreeting() throws Exception {
        when(request.getParameter("name")).thenReturn("John");
        
        servlet.doGet(request, response);
        writer.flush();
        
        verify(response).setContentType("text/html");
        assert(stringWriter.toString().contains("Hello John"));
    }

    @Test
    void doGet_withNameContainingHtmlCharacters_shouldEscapeHtml() throws Exception {
        when(request.getParameter("name")).thenReturn("<script>alert('XSS')</script>");
        
        servlet.doGet(request, response);
        writer.flush();
        
        verify(response).setContentType("text/html");
        String output = stringWriter.toString();
        assert(!output.contains("<script>"));
        assert(output.contains("&lt;script&gt;"));
    }

    @Test
    void doPost_shouldCallDoGet() throws Exception {
        when(request.getParameter("name")).thenReturn("John");
        
        servlet.doPost(request, response);
        writer.flush();
        
        verify(response).setContentType("text/html");
        assert(stringWriter.toString().contains("Hello John"));
    }
}