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

@WebServlet("/pwd.do")
public class PwdServlet extends HttpServlet {
    private static final long serialVersionUID = -8123085861273087650L;
    private static DataSource ds;

    private Logger logger = Logger.getLogger(getClass().getName());

    static {
        try {
            InitialContext ctx = new InitialContext();
            //DONE: OWASP A5:2017 - Broken Access Control (root privileges)
            ds = (DataSource) ctx.lookup("jdbc/MySQL_crud_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException {

        logger.info("Received request from " + request.getRemoteAddr());

        try (Connection connection = ds.getConnection()) {

          
            //usernmae is saved in session
            String username = (String) request.getSession().getAttribute("username");

            String password = request.getParameter("password");

            String oldPassword = request.getParameter("old");

            String confirmPassword = request.getParameter("confirm");

            //---Get the password by Username
            String query = "select password from users " +
                            "where username = ? ";

            PreparedStatement st = connection.prepareStatement(query);
             st.setString(1,username);

            ResultSet rs = st.executeQuery();

            if (!rs.next()) {
                logger.warning("User not found!");

                response.sendRedirect(response.encodeRedirectURL("failedChangePwd.jsp"));
                return;
            }

            if(!oldPassword.equalsIgnoreCase(rs.getString("password"))){
                logger.warning("old Password is not correct");
                response.sendRedirect(response.encodeRedirectURL("failedChangePwd.jsp"));
                return;
            }

            if(!password.equalsIgnoreCase(confirmPassword)){
                logger.warning("password doesnot match confirm password!");
                response.sendRedirect(response.encodeRedirectURL("failedChangePwd.jsp"));
                return;
            }


            if(oldPassword.equalsIgnoreCase(password)){
                logger.warning("new password match the old password");
                response.sendRedirect(response.encodeRedirectURL("failedChangePwd.jsp"));
                return;
            }

            //FIXME: OWASP A5:2017 - Broken Access Control
            // Security policies not checked:
            //  1) new password != old password
            //  2) minimum password age
            //  3) password complexity
            //  4) password length

            //Resolved it by Password Correction 
            query = String.format("update users " +
                            "set password = ? " +
                            "where username = ? ");

            //DONE: OWASP A3:2017 - Sensitive Data Exposure
            // Log reveals sensitive info
            logger.info("Query: " + query);

            //DOEN: OWASP A10:2017 - Insufficient Logging & Monitoring
            // return value not logged
            //DONE: OWASP A8:2013 - CSRF
            PreparedStatement stmt = connection.prepareStatement(query);
            stmt.setString(1, password);
            stmt.setString(2,username);
            int result=  stmt.executeUpdate();
            logger.info("update password. Affected rows : "+result);
            //DONE: OWASP A5:2017 - Broken Access Control
            //  Cookie used without any signature
            //DONE: OWASP A3:2017 - Sensitive Data Exposure
            //  Password stored as plaintext on client-side
            //DONE: OWASP A2:2017 - Broken Authentication
            //  Parameter "Remember me" is not observed
            //  Cookie security settings (httpOnly, secure, age, domain, path, same-site)
            //  For same-site, see: https://stackoverflow.com/a/43106260/459391
            //      response.setHeader("Set-Cookie", "key=value; HttpOnly; SameSite=strict")

            response.sendRedirect("user.jsp");

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
        }
    }

}