# Servlet 2.5+ 集成 {#servletapi-25}

本节介绍 Spring Security 是如何与 Servlet 2.5 规范进行集成的。

## HttpServletRequest.getRemoteUser() {#servletapi-remote-user}

[`HttpServletRequest.getRemoteUser()`](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getRemoteUser())
返回的是
`SecurityContextHolder.getContext().getAuthentication().getName()`
的结果，通常即为当前用户的用户名。这在需要显示当前用户名的应用中非常有用。
此外，你可以通过检查该方法返回值是否为 `null`
来判断用户是否已认证，或者仍处于匿名状态。
了解用户是否已认证有助于决定某些 UI
元素是否应被展示（例如，仅当用户已登录时才显示"退出"链接）。

## HttpServletRequest.getUserPrincipal() {#servletapi-user-principal}

[`HttpServletRequest.getUserPrincipal()`](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getUserPrincipal())
返回 `SecurityContextHolder.getContext().getAuthentication()` 的结果。
这意味着它返回一个 `Authentication`
对象，在使用基于用户名和密码的身份验证时，通常是
`UsernamePasswordAuthenticationToken` 的实例。
当你需要获取更多关于用户的信息时，这个方法非常有用。
例如，你可能创建了一个自定义的
`UserDetailsService`，返回一个包含用户姓名和姓氏的自定义 `UserDetails`
实例。 你可以通过以下代码获取这些信息：

::: informalexample

Java

:   ``` java
    Authentication auth = httpServletRequest.getUserPrincipal();
    // 假设集成了名为 MyCustomUserDetails 的自定义 UserDetails
    // 默认情况下，通常为 UserDetails 的实例
    MyCustomUserDetails userDetails = (MyCustomUserDetails) auth.getPrincipal();
    String firstName = userDetails.getFirstName();
    String lastName = userDetails.getLastName();
    ```

Kotlin

:   ``` kotlin
    val auth: Authentication = httpServletRequest.getUserPrincipal()
    // 假设集成了名为 MyCustomUserDetails 的自定义 UserDetails
    // 默认情况下，通常为 UserDetails 的实例
    val userDetails: MyCustomUserDetails = auth.principal as MyCustomUserDetails
    val firstName: String = userDetails.firstName
    val lastName: String = userDetails.lastName
    ```
:::

:::: note
::: title
:::

需要注意的是，在应用程序各处执行大量此类逻辑通常是一种不良实践。
更推荐的做法是将这些逻辑集中处理，以减少对 Spring Security 和 Servlet
API 的耦合。
::::

## HttpServletRequest.isUserInRole(String) {#servletapi-user-in-role}

[`HttpServletRequest.isUserInRole(String)`](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#isUserInRole(java.lang.String))
方法用于判断
`SecurityContextHolder.getContext().getAuthentication().getAuthorities()`
是否包含一个与传入角色名称匹配的 `GrantedAuthority`。
通常，调用此方法时不应包含 `ROLE_` 前缀，因为该前缀会自动添加。
例如，如果你想判断当前用户是否拥有 \"ROLE_ADMIN\"
权限，可以使用如下代码：

::: informalexample

Java

:   ``` java
    boolean isAdmin = httpServletRequest.isUserInRole("ADMIN");
    ```

Kotlin

:   ``` kotlin
    val isAdmin: Boolean = httpServletRequest.isUserInRole("ADMIN")
    ```
:::

这种方法可用于决定是否显示某些 UI 组件。
例如，仅当当前用户是管理员时才显示管理链接。

# Servlet 3+ 集成 {#servletapi-3}

本节描述 Spring Security 所集成的 Servlet 3 提供的方法。

## HttpServletRequest.authenticate(HttpServletRequest, HttpServletResponse) {#servletapi-authenticate}

你可以使用
[`HttpServletRequest.authenticate(HttpServletRequest, HttpServletResponse)`](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#authenticate%28javax.servlet.http.HttpServletResponse%29)
方法来确保用户已经完成身份验证。 如果用户未认证，系统将使用配置好的
`AuthenticationEntryPoint` 要求用户进行认证（例如重定向到登录页面）。

## HttpServletRequest.login(String, String) {#servletapi-login}

你可以使用
[`HttpServletRequest.login(String, String)`](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#login%28java.lang.String,%20java.lang.String%29)
方法，通过当前的 `AuthenticationManager` 对用户进行认证。
例如，以下代码尝试使用用户名 `user` 和密码 `password` 进行登录：

::: informalexample

Java

:   ``` java
    try {
        httpServletRequest.login("user", "password");
    } catch (ServletException ex) {
        // 认证失败
    }
    ```

Kotlin

:   ``` kotlin
    try {
        httpServletRequest.login("user", "password")
    } catch (ex: ServletException) {
        // 认证失败
    }
    ```
:::

:::: note
::: title
:::

如果你希望由 Spring Security 处理认证失败的情况，则无需捕获
`ServletException`。
::::

## HttpServletRequest.logout() {#servletapi-logout}

你可以使用
[`HttpServletRequest.logout()`](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#logout%28%29)
方法注销当前用户。

通常，这意味着 `SecurityContextHolder` 会被清空，`HttpSession`
将被失效，任何"记住我"（Remember Me）的认证信息也会被清除等。
然而，具体行为取决于你在 Spring Security 中配置的 `LogoutHandler` 实现。
注意：在调用 `HttpServletRequest.logout()`
后，你仍然需要负责输出响应内容。 通常，这包括重定向到欢迎页。

## AsyncContext.start(Runnable) {#servletapi-start-runnable}

[`AsyncContext.start(Runnable)`](https://docs.oracle.com/javaee/6/api/javax/servlet/AsyncContext.html#start%28java.lang.Runnable%29)
方法确保你的认证凭据能够传播到新线程中。 通过使用 Spring Security
的并发支持功能，Spring Security 会覆盖
`AsyncContext.start(Runnable)`，以确保在执行 `Runnable` 时使用当前的
`SecurityContext`。 以下示例输出当前用户的 `Authentication` 信息：

::: informalexample

Java

:   ``` java
    final AsyncContext async = httpServletRequest.startAsync();
    async.start(new Runnable() {
        public void run() {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            try {
                final HttpServletResponse asyncResponse = (HttpServletResponse) async.getResponse();
                asyncResponse.setStatus(HttpServletResponse.SC_OK);
                asyncResponse.getWriter().write(String.valueOf(authentication));
                async.complete();
            } catch(Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    });
    ```

Kotlin

:   ``` kotlin
    val async: AsyncContext = httpServletRequest.startAsync()
    async.start {
        val authentication: Authentication = SecurityContextHolder.getContext().authentication
        try {
            val asyncResponse = async.response as HttpServletResponse
            asyncResponse.status = HttpServletResponse.SC_OK
            asyncResponse.writer.write(String.valueOf(authentication))
            async.complete()
        } catch (ex: Exception) {
            throw RuntimeException(ex)
        }
    }
    ```
:::

## 异步 Servlet 支持 {#servletapi-async}

如果你使用基于 Java 的配置，那么默认已经支持异步请求。 若使用 XML
配置，则需要进行一些更新。 第一步是确保你的 `web.xml`
文件已升级至至少使用 3.0 版本的 schema：

``` xml
<web-app xmlns="http://java.sun.com/xml/ns/javaee"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://java.sun.com/xml/ns/javaee https://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
version="3.0">

</web-app>
```

接下来，你需要确保 `springSecurityFilterChain` 已配置为可处理异步请求：

``` xml
<filter>
<filter-name>springSecurityFilterChain</filter-name>
<filter-class>
    org.springframework.web.filter.DelegatingFilterProxy
</filter-class>
<async-supported>true</async-supported>
</filter>
<filter-mapping>
<filter-name>springSecurityFilterChain</filter-name>
<url-pattern>/*</url-pattern>
<dispatcher>REQUEST</dispatcher>
<dispatcher>ASYNC</dispatcher>
</filter-mapping>
```

现在，Spring Security 可以确保在异步请求中也能正确传递
`SecurityContext`。

那么它是如何工作的呢？如果你不感兴趣，可以跳过本节其余部分。
大部分机制都内建于 Servlet 规范中，但 Spring Security
做了一些调整，以确保异步请求下的正常工作。 在 Spring Security 3.2
之前，一旦 `HttpServletResponse` 被提交，`SecurityContextHolder` 中的
`SecurityContext` 就会自动保存。 这在异步环境下可能会引发问题。
考虑以下示例：

::: informalexample

Java

:   ``` java
    httpServletRequest.startAsync();
    new Thread("AsyncThread") {
        @Override
        public void run() {
            try {
                // 执行任务
                TimeUnit.SECONDS.sleep(1);

                // 写入并提交 httpServletResponse
                httpServletResponse.getOutputStream().flush();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }.start();
    ```

Kotlin

:   ``` kotlin
    httpServletRequest.startAsync()
    object : Thread("AsyncThread") {
        override fun run() {
            try {
                // 执行任务
                TimeUnit.SECONDS.sleep(1)

                // 写入并提交 httpServletResponse
                httpServletResponse.outputStream.flush()
            } catch (ex: java.lang.Exception) {
                ex.printStackTrace()
            }
        }
    }.start()
    ```
:::

问题在于，该线程并不被 Spring Security 所知，因此 `SecurityContext`
不会被传播到该线程。 这意味着当我们提交 `HttpServletResponse`
时，没有可用的 `SecurityContext`。 而旧版本的 Spring Security
在提交响应时会自动保存
`SecurityContext`，这就可能导致已登录用户的状态丢失。

从 3.2 版本开始，Spring Security 智能地避免了在调用
`HttpServletRequest.startAsync()` 后，于提交 `HttpServletResponse`
时自动保存 `SecurityContext` 的行为。

# Servlet 3.1+ 集成 {#servletapi-31}

本节描述 Spring Security 所集成的 Servlet 3.1 及以上版本的方法。

## HttpServletRequest#changeSessionId() {#servletapi-change-session-id}

[HttpServletRequest.changeSessionId()](https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletRequest.html#changeSessionId())
是 Servlet 3.1 及更高版本中用于防御 [会话固定（Session
Fixation）](servlet/authentication/session-management.xml#ns-session-fixation)
攻击的默认方法。
