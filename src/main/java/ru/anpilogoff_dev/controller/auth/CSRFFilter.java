package ru.anpilogoff_dev.controller.auth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.anpilogoff_dev.utils.CookieUtil;

import javax.servlet.*;
import javax.servlet.http.Cookie;
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
            Cookie cookieCSRF = CookieUtil.getCookieByName(request.getCookies(),"X-CSRF-TOKEN");
            String headerCsrf = request.getHeader("XSRF-TOKEN");

            if (headerCsrf == null || cookieCSRF == null ||!headerCsrf.equals(cookieCSRF.getValue())   ) {
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