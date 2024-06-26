package ru.anpilogoff_dev.controller.signup;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import ru.anpilogoff_dev.database.model.RegistrationStatus;
import ru.anpilogoff_dev.database.model.UserDataObject;
import ru.anpilogoff_dev.database.model.UserModel;
import ru.anpilogoff_dev.service.EmailService;
import ru.anpilogoff_dev.service.SignUpService;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

/**
 * Сервлет, обрабатывающий запросы регистрации пользователя.
 * Поддерживает операции регистрации и подтверждения регистрации через email.
 */
public class SignUpServlet extends HttpServlet {
    private static final Logger log = LogManager.getLogger("HttpRequestLogger");
    private SignUpService signupService;
    private EmailService emailService;

    /**
     * Инициализирует сервлет, получая ссылки на сервисы регистрации и отправки email из контекста сервлета.
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.emailService = (EmailService) config.getServletContext().getAttribute("emailService");
        this.signupService = (SignUpService) config.getServletContext().getAttribute("userDataService");
    }

    /**
     * Обрабатывает GET-запросы, предназначенные для подтверждения регистрации пользователя.
     * Если параметр подтверждения присутствует в запросе, пытается подтвердить регистрацию.
     * В случае успеха перенаправляет на главную страницу.
     *
     * @param req  HTTP-запрос
     * @param resp HTTP-ответа
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (req.getQueryString() != null && req.getQueryString().contains("confirmation")) {
           boolean isConfirmed = signupService.confirmRegistration(req.getParameter("confirmation"));

           if(isConfirmed){
               resp.sendRedirect("/home");
           }
        }else {
            req.getRequestDispatcher("signup.html").forward(req,resp);
        }
    }

    /**
     * Обрабатывает POST-запросы, предназначенные для регистрации нового пользователя.
     * Извлекает данные пользователя из запроса и регистрирует его в системе c помощью сервиса регистрации.
     * Отправляет email с кодом подтверждения, если регистрация прошла успешно. Используя для этого EmailService.
     *
     * @param req  HTTP-запрос
     * @param resp HTTP-ответ
     * @see SignUpService
     * @see EmailService
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        log.info("SignupServlet: " + req.getRequestURI()+  "    " );

        Writer writer = resp.getWriter();

        UserModel userModel = new UserModel(
                req.getParameter("login"),
                req.getParameter("password"),
                req.getParameter("email"),
                req.getParameter("nickname")
        );

        UserDataObject object = new UserDataObject(userModel, RegistrationStatus.UNKNOWN);

        //попытка регистрации нового пользователя
        object = signupService.registerUser(object);
        JSONObject responseJson = new JSONObject();

        switch (object.getRegistrationStatus()){
            case REG_SUCCESS:
                log.debug("  --registration success: " + object);

                emailService.sendConfirmationEmail(object.getUserModel().getEmail(),object.getConfirmCode());
                responseJson.put("success",true);
                break;
            case REG_ERROR:
                log.debug("  --registration error:"+object);

                responseJson.put("success",false);
                responseJson.put("reason","server error");
                break;
        }
        writer.write(responseJson.toString());
        writer.flush();
        writer.close();
    }
}
