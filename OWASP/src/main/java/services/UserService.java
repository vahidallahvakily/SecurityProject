package services;

import org.jasypt.util.password.StrongPasswordEncryptor;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.sql.*;

public class UserService {

    private static Logger logger = Logger.getLogger("UserService");
    private static DataSource ds;
    private static SecureRandom random = new SecureRandom();
    private static Map<String, String> rememberedUsers = new HashMap<>();

    static String username;
    static String password;
    static String role;
    static String jasypt_pass;

    static {
        try {
            InitialContext ctx = new InitialContext();
            ds = (DataSource) ctx.lookup("jdbc/MySQL_crud_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
    public static boolean isAuthenticUser(String userParam, String passParam,
                                          HttpServletRequest request,
                                          HttpServletResponse response) throws IOException {

        try (Connection connection = ds.getConnection()) {

            // Prepared statements are NOT susceptible to SQL Injection
            PreparedStatement pstmt = connection.prepareStatement(
                    "select * from users where username = ?  LIMIT 1");

            pstmt.setString(1, userParam);

            ResultSet rs = pstmt.executeQuery();

            if (!rs.next()) {
                logger.info("User not found!");

                response.sendRedirect("failed.jsp");
                return false;
            }
            StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();

            jasypt_pass = rs.getString("password");

            if (!passwordEncryptor.checkPassword(passParam, jasypt_pass)) {
                logger.warning(String.format("Attempted login by username %s with wrong password.",
                        userParam));

                // The error should NOT differ from the case where username is wrong,
                // to prevent "username harvesting"
                response.sendRedirect(String.format("%s/error.jsp?errno=0", request.getContextPath()));
                return false;
            }

            username = rs.getString("username");
            password = rs.getString("password");
            role = rs.getString("role");
            int userId = rs.getInt("id");


            pstmt = connection.prepareStatement(
                    "update users set LAST_LOGON = CURRENT_TIMESTAMP where id = ? LIMIT 1");
            pstmt.setInt(1, userId);
            pstmt.executeUpdate();
            request.getSession().setAttribute("username",username);
            request.getSession().setAttribute("userId",userId);
            request.getSession().setAttribute("role",role);

            return true;

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
            response.sendRedirect("failed.jsp");
            return false;
        }
    }

    public static String rememberUser(String username) {

        String randomId = new BigInteger(130, random).toString(32);
        rememberedUsers.put(randomId, username);
        return randomId;

    }

    public static String getRememberedUser(String id) {
        return rememberedUsers.get(id);
    }

    public static void removeRememberedUser(String id) {
        rememberedUsers.remove(id);
    }

}
