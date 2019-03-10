package servlets;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.jasypt.util.password.StrongPasswordEncryptor;

@WebServlet("/login.do")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = -1813590570829849128L;
    private static DataSource ds;

    private static Pattern usernamePattern = Pattern.compile("^[A-Za-z0-9_.]+$");
    private Logger logger = Logger.getLogger(getClass().getName());

    static {
        try {
            InitialContext ctx = new InitialContext();
            ds = (DataSource) ctx.lookup("jdbc/MySQL_root_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request,
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

        //FIXME: OWASP A7:2017 - Cross-Site Scripting (XSS)
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

        //FIXME: OWASP A1:2017 - Injection
        //FIXME: Use "LIMIT 1" at the end of query to improve performance
        /*String query = String.format("select * from users " +
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
        }*/


        logger.info("Received request from " + request.getRemoteAddr());

        String username, password, role;
        String jasypt_pass;

        try (Connection connection = ds.getConnection()) {

            // Prepared statements are NOT susceptible to SQL Injection
            PreparedStatement pstmt = connection.prepareStatement(
                    "select * from users where username = ?  LIMIT 1");

            pstmt.setString(1, userParam);

            ResultSet rs = pstmt.executeQuery();

            if (!rs.next()) {
                logger.info("User not found!");

                response.sendRedirect("failed.jsp");
                return;
            }
            StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();

            jasypt_pass = rs.getString("password");

            if (!passwordEncryptor.checkPassword(passParam, jasypt_pass)) {
                logger.warning(String.format("Attempted login by username %s with wrong password.",
                        userParam));

                // The error should NOT differ from the case where username is wrong,
                // to prevent "username harvesting"
                response.sendRedirect(String.format("%s/error.jsp?errno=0", request.getContextPath()));
                return;
            }

            username = rs.getString("username");
            password = rs.getString("password");
            role = rs.getString("role");
            int userId = rs.getInt("id");


            pstmt = connection.prepareStatement(
                    "update users set LAST_LOGON = CURRENT_TIMESTAMP where id = ? LIMIT 1");
            pstmt.setInt(1, userId);
            pstmt.executeUpdate();


        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
            response.sendRedirect("failed.jsp");
            return;
        }

        request.getSession().setAttribute("username",username);
        request.getSession().setAttribute("role",role);
        //FIXME: OWASP A5:2017 - Broken Access Control
        //  Cookie used without any signature
        Cookie uCookie = new Cookie("token", username);
        response.addCookie(uCookie);



        response.sendRedirect("user.jsp");
    }
}