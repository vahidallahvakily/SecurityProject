package servlets;

import com.vaadin.server.Page;
import com.vaadin.server.VaadinSession;
import services.UserService;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;
import java.util.Optional;

import static servlets.LoginServlet.deleteRememberMeCookie;
import static servlets.LoginServlet.getRememberMeCookie;

@WebServlet("/logout.do")
public class LogoutServlet extends HttpServlet {
    private static final long serialVersionUID = -7529404061769958490L;


    @Override
    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException {

        //DONE: OWASP A2:2017 - Broken Authentication
        //FIXED By Calling deleteCookies
        HttpSession session = request.getSession();
        session.invalidate();
        deleteCookies(request,response);
        response.sendRedirect("index.jsp");
    }

    private void deleteCookies(HttpServletRequest request,
                               HttpServletResponse response) {
        Optional<Cookie> cookie = getRememberMeCookie(request);
        if (cookie.isPresent()) {
            String id = cookie.get().getValue();
            UserService.removeRememberedUser(id);
            deleteRememberMeCookie(response);
        }
        for (Cookie c : request.getCookies()) {
            c.setMaxAge(0);
            c.setValue(null);
            response.addCookie(c);

        }
        VaadinSession.getCurrent().close();
        Page.getCurrent().setLocation("");
    }

}