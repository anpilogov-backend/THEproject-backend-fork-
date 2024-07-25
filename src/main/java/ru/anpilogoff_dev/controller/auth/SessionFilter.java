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
import java.util.Arrays;

public class SessionFilter implements Filter {

    private static final Logger log = LogManager.getLogger("DebugLogger");

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession(false);
        String uri = request.getRequestURI();

        log.debug("SESSION FILTER:        ");
        log.debug("  + -- requestURI:  "+request.getRequestURI());

        if (session != null && session.getAttribute("user") != null) {

            log.debug("   -- SESSION  and session.USER attribute not null: ( "+session.getAttribute("user")+" )");

            if (uri.contains("auth")) {
                log.debug("   -- uri contain AUTH");
                Cookie jsessionCookie = CookieUtil.getCookieByName(request.getCookies(),"JSESSIONID");

                if(jsessionCookie != null){
                    jsessionCookie.setMaxAge(0);

                    response.addCookie(jsessionCookie);

                    log.debug("   -- cookie-max age set to 0: "+jsessionCookie.getName()+" : "+jsessionCookie.getValue()+" - added to response \n");
                    }
                log.debug(" -- session: "+session.getId());
                        session.invalidate();
                log.debug("   -- ...invalidated");

                response.sendRedirect("/auth");
                log.debug("   -- redirected from session filter on /auth \n");

                return;
            } else if (uri.contains("signup")) {
                log.debug("   -- redirected from session filter on /home \n");
                response.sendRedirect("/home");
                return;
            }
        }else if (session != null && uri.contains("home")){
            session.invalidate();
            response.sendRedirect("/auth");
            return;
        }else if(session == null && !uri.contains("auth") && !uri.contains("signup")){
            log.debug("   -- session is null..uri don't contains #auth# or #signup#");
            response.sendRedirect("/auth");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
