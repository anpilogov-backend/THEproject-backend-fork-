package ru.anpilogoff_dev.controller.auth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.IOException;
import java.util.UUID;

public class AuthServlet extends HttpServlet {
    private static final Logger log = LogManager.getLogger("DebugLogger");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        String csrfToken;

        if(session!=null){
            System.out.println(session.getAttribute("csrfToken") + "       TOKEH");
            request.setAttribute("csrfToken",session.getAttribute("csrfToken"));
        }

        // Проверка, есть ли уже токен в сессии
        if(session == null){
            session = request.getSession(true);
            csrfToken = generateCSRFToken();


            log.debug("CSRF token set as request attribute: " + csrfToken);

            String header = response.getHeader("Set-Cookie").replace("THEproject", "")+"; SameSite=Strict";
            response.setHeader("Set-Cookie", header);

            //      Cookie cookie = new Cookie("XSRF-TOKEN",csrfToken);
           // cookie.setSecure(true);
          //  cookie.setHttpOnly(false);
          //  cookie.setPath("/");
          //  response.addCookie(cookie);
            response.addHeader("Set-Cookie","XSRF-TOKEN="+csrfToken+"; Path=/; Secure; SameSite=Strict");



        }

        request.getServletContext().getRequestDispatcher("/login.jsp").forward(request, response);

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        HttpSession currentSession = req.getSession(false);
        log.debug("Auth servlet:  ");
        log.debug("   -- /auth:POST");

        log.debug("   -- session existed?:   " + currentSession);

        if(currentSession.getAttribute("csrfToken").equals(req.getParameter("csrfToken"))){
            currentSession.invalidate();
            currentSession = req.getSession(true);
            currentSession.setAttribute("csrfToken", generateCSRFToken());
            currentSession.setAttribute("user","testo-user");
            log.debug("   -- session attribute *user* applied");

            String header = resp.getHeader("Set-Cookie").replace("THEproject", "");
            resp.setHeader("Set-Cookie", header);
        }
        //UserModel =  authService.authenticateUser(UserModel model)
        //   -- если authService return true
        //          -> создаём сессию и устанавливаем куку(JSESSIONID, устанавливаем атрибут сессии "JSESSIONID"";
        //          -> генерим csrf токен и добавляем его  в тэг <meta> - req.setAttribute("token",val) -> ${"token"}
        //          -> на клиенте при отправке запросов на сервер берем из тэга токен и добавляем его в заголовок запроса
        log.debug("   -- new session created ID:  "+currentSession.getId());


        //"secure" + "httpOnly" settings appends in server.xml (<Connector>)

        resp.sendRedirect("/home");


        log.debug("   -- response redirected to home");

    }

    private static String generateCSRFToken(){
        return UUID.randomUUID().toString();
    }

}
