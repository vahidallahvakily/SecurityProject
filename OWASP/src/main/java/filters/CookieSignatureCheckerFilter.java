package filters;

import servlets.util.SecurityWebUtil;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

public class CookieSignatureCheckerFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String username = getCookieByName(req, "username");
        String role = getCookieByName(req, "role");
        String password = getCookieByName(req, "password");

        if ( (Optional.ofNullable(username).isPresent() &&  !SecurityWebUtil.verifyCookieSignature(username))
                || (Optional.ofNullable(role).isPresent() &&  !SecurityWebUtil.verifyCookieSignature(role))
                || (Optional.ofNullable(password).isPresent() &&  !SecurityWebUtil.verifyCookieSignature(password))
                ) {
            res.sendError(HttpServletResponse.SC_FORBIDDEN);
        } else {
            chain.doFilter(request, response);
        }
    }

    @SuppressWarnings("SameParameterValue")
    private String getCookieByName(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null)
            return null;
        Optional<Cookie> optional = Arrays.stream(cookies)
                .filter(x -> x.getName().equals(name))
                .findFirst();
        return optional.map(Cookie::getValue).orElse(null);
    }

    @Override
    public void destroy() {

    }
}
