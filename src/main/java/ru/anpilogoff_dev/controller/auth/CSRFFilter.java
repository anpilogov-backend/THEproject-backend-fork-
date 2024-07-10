package ru.anpilogoff_dev.controller.auth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class CSRFFilter implements Filter {
    private static final Logger log = LogManager.getLogger("DebugLogger");

    @Override
    public void init(FilterConfig filterConfig) {}



    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        log.debug("CSRFFilter:   ");
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession(false);

        if (request.getMethod().equalsIgnoreCase("POST") && session != null) {
            String csrfToken = request.getParameter("csrfToken");
            String sessionToken = (String) session.getAttribute("csrfToken");

            if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                session.invalidate();
                log.debug( "    -- CSRF токен не совпадает или отсутствует. Session Invalidated");
                response.sendRedirect("/auth");
                return;
            }
            log.debug("   -- токены совпадают");
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}
