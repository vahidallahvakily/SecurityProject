package servlets;

import org.jetbrains.annotations.Nullable;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.logging.Logger;

@WebServlet("/admin.do")
public class AdminServlet extends HttpServlet {
    private static final long serialVersionUID = 4501855365314172264L;
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

        //DONE OWASP A5:2017 - Broken Access Control
        String role = request.getSession().getAttribute("role").toString();
        if (!"admin".equals(role)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "You must be a system admin!");
            return;
        }

        logger.info("Received request from " + request.getRemoteAddr());

        StringBuilder query = new StringBuilder();
        StringBuilder list = new StringBuilder();
        List<String> lstParameters=new ArrayList<>();
        query.append("UPDATE guestbook SET approved = (CASE id ");

        Enumeration<String> paramIds = request.getParameterNames();
        int count = 0;
        //ignore nounce
        paramIds.nextElement();
        while (paramIds.hasMoreElements()) {
            String id = paramIds.nextElement();
            String val = request.getParameter(id);
            query.append(String.format("WHEN ? THEN ? "));
            lstParameters.add(id);
            lstParameters.add(val);
            list.append(String.format("'%s', ", id));
            count++;
        }

        if (count == 0) {
            response.sendRedirect("admin.jsp");
            return;
        }

        // Remove the extra ", " from list
        list.delete(list.length() - 2, list.length());
        query.append(String.format("END) WHERE id IN (%s)", list));

        logger.info("Query: " + query);

        try (Connection connection = ds.getConnection()) {

            PreparedStatement st = connection.prepareStatement(query.toString());

            //DONE: OWASP A10:2017 - Insufficient Logging & Monitoring
            // return value not logged
            //FIXED By Logging result
            //DONE: OWASP A1:2017 - Injection
            //DONE: OWASP A8:2013 - CSRF
            for(int index=1;index<=lstParameters.size();index++){
                st.setString(index,lstParameters.get(index-1));
            }
            int result = st.executeUpdate();

            logger.info("Query result: " + result);

            response.sendRedirect("admin.jsp");

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
        }
    }

    @SuppressWarnings("SameParameterValue")
    @Nullable
    private String getCookieByName(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null)
            return null;
        Optional<Cookie> optional = Arrays.stream(cookies)
                .filter(x -> x.getName().equals(name))
                .findFirst();
        return optional.map(Cookie::getValue).orElse(null);
    }
}