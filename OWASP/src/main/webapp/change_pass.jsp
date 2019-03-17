<html>
<head>
    <title>Change Password</title>
    <jsp:include page="common.jsp"/>
</head>
<body>
<div class="container">
    <h1 class="row">Change You Password</h1>

    <hr>

    <form id="frmChangePassword" action="pwd.do" method="post">
        <INPUT type="HIDDEN" name="CSRF_NONCE" value="<%=response.encodeURL(null)%>">
        <%--DONE: OWASP A2:2017 - Broken Authentication
            Username is determined based on client-provided information
        --%>
        <input type="hidden"
               name="username" id="username"
               value="${cookie['username'].value}">

        <div class="form-group">
            <label for="old">Old Password:</label>
            <input class="form-control" type="password"
                   name="old" id="old"
                   placeholder="Old Password">
        </div>

        <div class="form-group">
            <label for="password">New Password:</label>
            <input class="form-control" type="password"
                   name="password" id="password"
                   placeholder="New password">
        </div>

        <div class="form-group">
            <label for="confirm">Confirm Password:</label>
            <input class="form-control" type="password"
                   name="confirm" id="confirm"
                   placeholder="Confirm password">
        </div>

        <button type="submit" class="btn btn-warning btn-lg">Submit</button>
    </form>
</div>
<script src="/static/js/other.js" />
</body>
</html>