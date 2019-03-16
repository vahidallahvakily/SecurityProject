package filters;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *  *
 *  * @author V_Alahvakil
 *    CreateDateTime 3/8/2019
 *  
 */
@WebFilter("/*")
public class AuthenticationFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {




        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpServletRequest httpRequest= (HttpServletRequest) request;



        if(httpRequest.getRequestURI().equals("/")){
            if(httpRequest.getSession()!=null &&
             httpRequest.getSession().getAttribute("username")!=null && httpRequest.getSession().getAttribute("username")!=""){
                ((HttpServletResponse) response).sendRedirect("/user.jsp");
                return;
            }
        }
        if(httpRequest.getRequestURI().equals("/index.jsp") ||
                httpRequest.getRequestURI().equals("/") ||
                httpRequest.getRequestURI().startsWith("/login.do") ||
                httpRequest.getRequestURI().startsWith("/static/") ||
                httpRequest.getRequestURI().equals("/error.jsp") ||
                httpRequest.getRequestURI().equals("/failed.jsp")){
            chain.doFilter(request, response);
            return;
        }
       if(httpRequest.getSession(true)!=null &&  httpRequest.getSession(true).getAttribute("username")!=null &&
               !httpRequest.getSession().getAttribute("username").toString().equalsIgnoreCase("")){
            if(httpRequest.getRequestURI().startsWith("/admin")){
                if (!"admin".equals(httpRequest.getSession().getAttribute("role").toString())) {
                    ((HttpServletResponse) response).sendRedirect("/unauthorized.jsp");
                }
                chain.doFilter(request, response);
            }else{
                chain.doFilter(request, response);
            }
       }
       else{
           ((HttpServletResponse) response).sendRedirect("/");
       }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void destroy() {

    }

}
