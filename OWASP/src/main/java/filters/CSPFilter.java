package filters;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
 See "org.apache.catalina.filters":
    https://tomcat.apache.org/tomcat-8.0-doc/api/org/apache/catalina/filters/package-frame.html
 Notable filters:
    CsrfPreventionFilter
    CsrfPreventionFilter.CsrfResponseWrapper
    CsrfPreventionFilter.LruCache
    CsrfPreventionFilterBase
    HttpHeaderSecurityFilter
    RestCsrfPreventionFilter
 None provides CSP!
*/


@WebFilter("/*")
public class CSPFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        chain.doFilter(request, response);
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpServletRequest httpRequest= (HttpServletRequest) request;
        httpResponse.setHeader("Content-Security-Policy", "script-src 'self'");
        httpResponse.setHeader("Set-Cookie", "HttpOnly; SameSite=strict");
        httpResponse.setHeader("X-XSS-Protection", "0");

    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        
    }

    @Override
    public void destroy() {
        
    }
}
