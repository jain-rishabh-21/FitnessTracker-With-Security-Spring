<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>
<head>
    <title>
        Login Page
    </title>
    <style type="text/css">
        .errorblock {
            color: #ff0000;
            background-color: #ffEEEE;
            border: 3px solid #ff0000;
            padding: 8px;
            margin: 16px;
        }
    </style>
</head>

<body onload='document.f.j_username.focus();'>
<h3>
    Login Page
</h3>
<c:if test="${not empty error}">
    <div class="errorblock">
        Your login was unsuccessful <br>
        Casued by: ${sessionScope["SPRING_SECURITY_LAST_EXCEPTION"].message}
    </div>
</c:if>

<form action="j_spring_security_check" name="f" method="post">
    <table>
        <tr>
            <td>
                User:
            </td>
            <td>
                <input type="text" name="j_username" value="">
            </td>
        </tr>
        <tr>
            <td>
                Password:
            </td>
            <td>
                <input type="text" name="j_password" value="">
            </td>
        </tr>
        <tr>
            <td >
                <input type="submit" name="Submit" value="Submit">
            </td>
            <td >
                <input type="reset" name="reset">
            </td>
        </tr>

    </table>
</form>
</body>
</html>
