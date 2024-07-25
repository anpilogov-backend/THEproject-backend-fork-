package ru.anpilogoff_dev.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.http.Cookie;

public class CookieUtil {
    private static final Logger log = LogManager.getLogger("DebugLogger");

    public static Cookie getCookieByName(Cookie [] cookies, String cookieName){
        log.debug("CookieUtil.getJsessionIdCookie():  ");
        Cookie resultCookie = null;

        if (cookies != null && cookies.length != 0) {

            log.debug("   -- cookies != null");

            for (Cookie cookie : cookies) {
                if (cookie != null && cookie.getName().equals(cookieName)) {
                    log.debug( cookie.getName() +"   -- JSESSIONID cookie");
                    resultCookie = cookie;

                    log.debug("   -- break");
                    break;
                }
            }
        }
        log.debug("  --return:  "+resultCookie);

        return resultCookie;
    }
}
