package control;


import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ContentSecurityPolicyFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Inizializzazione del filtro se necessario
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Aggiungi l'header Content-Security-Policy con frame-ancestors
        httpResponse.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'self';");
        
        // Aggiungi l'header X-Frame-Options
        httpResponse.setHeader("X-Frame-Options", "SAMEORIGIN");
        
        // Passa la richiesta e la risposta lungo la catena di filtri
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Pulizia del filtro se necessario
    }
}