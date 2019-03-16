package servlets;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import com.vaadin.server.VaadinService;
import com.vaadin.server.VaadinSession;
import services.UserService;

@WebServlet("/login.do")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = -1813590570829849128L;
    private static DataSource ds;

    private static Pattern usernamePattern = Pattern.compile("^[A-Za-z0-9_.]+$");
    private Logger logger = Logger.getLogger(getClass().getName());

    private static final String COOKIE_NAME = "remember-me";
    public static final String SESSION_USERNAME = "username";



    @Override
    protected void doPost(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException {


        logger.info("Received request from " + request.getRemoteAddr());

        String userParam = request.getParameter("username");
        String passParam = request.getParameter("password");

        if (!usernamePattern.matcher(userParam).matches()) {
            logger.warning("Invalid characters in username.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid characters in username.");
            return;
        }

        //DONE: OWASP A7:2017 - Cross-Site Scripting (XSS)
        // Category: Reflected XSS (AKA Non-Persistent or Type II)
        // Category: Server XSS

        // Resolution 1: Use Content-Security-Policy (CSP)
        // Resolution 2: Sanitize input (as always!)
        if (userParam == null || passParam == null) {
            response.setContentType("text/html; charset=UTF-8");

            // NOTE: Internet Explorer, Chrome and Safari have a builtin "XSS filter" to prevent this.
            // Unless "X-XSS-Protection" is disabled, as shown below:

            // response.setHeader("X-XSS-Protection", "0");

            // Firefox, however, does not prevent reflected XSS.
            // See "Firefox - X-XSS-Protection Support.txt" for more info!

            return;
        }

        //DONE: OWASP A1:2017 - Injection
        //DONE: Use "LIMIT 1" at the end of query to improve performance

        if (isAuthenticated(request) || UserService.isAuthenticUser(userParam, passParam, request, response)) {
                request.setAttribute(SESSION_USERNAME, userParam);
           if (request.getAttribute("remember") != null && Boolean.parseBoolean( request.getAttribute("remember").toString())) {
                rememberUser(userParam, response);
            }
            response.sendRedirect("user.jsp");
        }

        //FIXME: OWASP A5:2017 - Broken Access Control
        //  Cookie used without any signature
/*        Cookie uCookie = new Cookie("token", username);
        response.addCookie(uCookie);*/


    }

    public static boolean isAuthenticated(HttpServletRequest request) {
        return request.getSession().getAttribute(SESSION_USERNAME) != null
                || loginRememberedUser(request);

    }

    public static Optional<Cookie> getRememberMeCookie(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();
        return Arrays.stream(cookies)
                .filter(c -> c.getName().equals(COOKIE_NAME))
                .findFirst();
    }

    private static boolean loginRememberedUser(HttpServletRequest request) {

        Optional<Cookie> rememberMeCookie = getRememberMeCookie(request);

        if (rememberMeCookie.isPresent()) {
            String id = rememberMeCookie.get().getValue();
            String username = UserService.getRememberedUser(id);
            if (username != null) {
                VaadinSession.getCurrent().setAttribute(SESSION_USERNAME, username);
                return true;
            }
        }
        return false;
    }

    private static void rememberUser(String username, HttpServletResponse response) {
        String id = UserService.rememberUser(username);
        Cookie cookie = new Cookie(COOKIE_NAME, id);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 24 * 30); // valid for 30 days
        response.addCookie(cookie);
    }

    public static void deleteRememberMeCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}