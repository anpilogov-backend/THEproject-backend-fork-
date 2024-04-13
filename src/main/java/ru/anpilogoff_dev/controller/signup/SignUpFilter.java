package ru.anpilogoff_dev.controller.signup;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.anpilogoff_dev.database.model.UserDataObject;
import ru.anpilogoff_dev.database.model.UserModel;
import ru.anpilogoff_dev.service.SignUpService;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SignUpFilter implements Filter {
    private static final Logger log = LogManager.getLogger("HttpRequestLogger");

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse resp = (HttpServletResponse) servletResponse;
        Writer writer = resp.getWriter();

        if (req.getSession(false) != null && req.getHeader("Authorization") != null) {
            resp.sendRedirect(req.getServletContext().getContextPath() + "/home");
        } else {
            SignUpService service = (SignUpService) req.getServletContext().getAttribute("userDataService");

            List<String> params = new ArrayList<>();
                boolean allParamsValid = Collections.list(req.getParameterNames())
                        .stream()
                        .allMatch(param -> {
                            String paramVal = req.getParameter(param);
                            if (paramVal!= null && !paramVal.isEmpty()) {
                                params.add(paramVal);
                                return true;
                            }
                            return false;
                        });
            if (allParamsValid ) {
                log.debug("SignupFilter: params validation passed -> Service.checkIsUserExist()");
                UserDataObject object = service.checkIsUserExist(
                        new UserModel(params.get(0), params.get(1), params.get(2), params.get(3)));

                if (object == null) {
                    log.info("SignupFilter: NOT EXISTS");
                    filterChain.doFilter(servletRequest, servletResponse);
                } else {
                    switch (object.getConfirmStatus()) {
                        case CONFIRMED_LOGIN:
                            writer.write("User with your login. r already registered...");
                            //TODO ответ в json
                            break;
                        case CONFIRMED_EMAIL:
                            //TODO ответ в json
                            writer.write("User with ..your... email r already registered...");
                            break;
                        case CONFIRMED_NICKNAME:
                            //TODO ответ в json
                            writer.write("User with ..your.. nickname r already registered..");
                            break;
                        case UNCONFIRMED:
                            log.debug("SignupLogger: {registered:unconfirmed");
                            //TODO ответ в json
                            writer.write("User with your creds. r already registered but needs confirmation");
                            break;
                    }
                    writer.flush();
                }
            }
        }
    }
}