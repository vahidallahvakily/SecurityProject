package servlets;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

@WebServlet("/login.do")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = -1813590570829849128L;
    private static DataSource ds;

    private Logger logger = Logger.getLogger(getClass().getName());

    private static Pattern usernamePattern = Pattern.compile("^[A-Za-z0-9_.]+$");

    static {
        try {
            InitialContext ctx = new InitialContext();
            ds = (DataSource) ctx.lookup("jdbc/MySQL_readonly_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException {

        logger.info("Received request from " + request.getRemoteAddr());

        HttpSession session = request.getSession(false);
        String csrf = request.getParameter("csrf");

        if (session == null
                || csrf == null
                || csrf.length() != 32
                || !csrf.equals(session.getAttribute("csrf"))) {

            logger.info("CSRF detected!");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF detected!");
            return;
        }

        session.removeAttribute("csrf");

        if (session.getAttribute("userId") != null) {
            logger.warning("User already logged in...");
            response.sendRedirect(String.format("%s/error.jsp?errno=4", request.getContextPath()));
            return;
        }

        String userParam = request.getParameter("username");
        String passParam = request.getParameter("password");

        if (userParam.length() > 50 || passParam.length() > 50) {
            logger.warning("Too long username or password.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Too long username or password.");
            return;
        }

        if (!usernamePattern.matcher(userParam).matches()) {
            logger.warning("Invalid characters in username.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid characters in username.");
            return;
        }

        String jasypt_pass;
        int userId;
        List<String> groups = new ArrayList<>();


        //FIXME: OWASP A1:2017 - Injection
        //FIXME: Use "LIMIT 1" at the end of query to improve performance
        String query = String.format("select * from users " +
                        "where username = '%s' " +
                        "and password = '%s'",
                userParam, passParam);


        //FIXME: OWASP A3:2017 - Sensitive Data Exposure
        logger.info("Query: " + query);

        String username, password, role;

        try (Connection connection = ds.getConnection()) {

            Statement st = connection.createStatement();

            ResultSet rs = st.executeQuery(query);

            if (!rs.next()) {
                logger.warning("User not found!");

                response.sendRedirect(response.encodeRedirectURL("failed.jsp"));
                return;
            }

            username = rs.getString("username");
            password = rs.getString("password");
            role = rs.getString("role");

            logger.info("User found.");

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
            response.sendRedirect("failed.jsp");
            return;
        }

        session.invalidate();
        session = request.getSession(true);

        //session.setAttribute("userId", userId);
        session.setAttribute("username", userParam);
        session.setAttribute("groups", groups);
        session.setAttribute("loginTime", Instant.now());

        if (groups.contains("admins"))
            response.sendRedirect(String.format("%s/admins/", request.getContextPath()));
        else if (groups.contains("users"))
            response.sendRedirect(String.format("%s/users/", request.getContextPath()));
        else if (groups.contains("guests"))
            response.sendRedirect(String.format("%s/guests.html", request.getContextPath()));
        else
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "You are group-less!");
    }
}