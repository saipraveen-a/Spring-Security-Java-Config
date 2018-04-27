<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html>
<head>
    <meta content="text/html; charset=UTF-8">
    <title>Home</title>
</head>
<body>
<h2>Welcome to spring security tutorial Home Page!</h2>

<a href="/admin">Click here to go to Admin Page</a>
<br/>
<a href="/welcome">Click here to go to Welcome Page</a>

<c:url value="/logout" var="logoutUrl" />
<form id="logout" action="${logoutUrl}" method="post" >
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
</form>

<c:if test="${pageContext.request.userPrincipal.name != null}">
    <a href="javascript:document.getElementById('logout').submit()">Logout</a>
</c:if>

</body>
</html>
