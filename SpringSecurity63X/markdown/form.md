Spring Security 支持通过 HTML 表单提供用户名和密码。
本节详细介绍基于表单的认证在 Spring Security 中的工作机制。

本节探讨基于表单的登录在 Spring Security 中如何工作。
首先，我们来看用户是如何被重定向到登录表单的：

<figure>
<img
src="servlet/authentication/unpwd/loginurlauthenticationentrypoint.png"
alt="loginurlauthenticationentrypoint" />
<figcaption>重定向到登录页面</figcaption>
</figure>

上述图示是在
[`SecurityFilterChain`](servlet/architecture.xml#servlet-securityfilterchain)
结构图的基础上构建的。

![number 1]({icondir}/number_1.png)
首先，用户向其未授权的资源（`/private`）发起未经身份验证的请求。

![number 2]({icondir}/number_2.png) Spring Security 的
[`AuthorizationFilter`](servlet/authorization/authorize-http-requests.xml)
判断该未认证请求为 *拒绝访问*，并抛出 `AccessDeniedException` 异常。

![number 3]({icondir}/number_3.png)
由于用户尚未认证，[`ExceptionTranslationFilter`](servlet/architecture.xml#servlet-exceptiontranslationfilter)
启动 *认证流程*，并通过配置的
[`AuthenticationEntryPoint`](servlet/authentication/architecture.xml#servlet-authentication-authenticationentrypoint)
将请求重定向到登录页面。 大多数情况下，`AuthenticationEntryPoint` 是
{security-api-url}org/springframework/security/web/authentication/LoginUrlAuthenticationEntryPoint.html\[`LoginUrlAuthenticationEntryPoint`\]
的实例。

![number 4]({icondir}/number_4.png) 浏览器请求被重定向到的登录页面。

![number 5]({icondir}/number_5.png) 应用程序内部必须
[渲染登录页面](#servlet-authentication-form-custom)。

当用户名和密码提交后，`UsernamePasswordAuthenticationFilter`
负责对用户名和密码进行认证。 `UsernamePasswordAuthenticationFilter`
继承自
[AbstractAuthenticationProcessingFilter](servlet/authentication/architecture.xml#servlet-authentication-abstractprocessingfilter)，因此以下图示看起来非常相似：

<figure>
<img
src="servlet/authentication/unpwd/usernamepasswordauthenticationfilter.png"
alt="usernamepasswordauthenticationfilter" />
<figcaption>认证用户名和密码</figcaption>
</figure>

该图示同样基于我们的
[`SecurityFilterChain`](servlet/architecture.xml#servlet-securityfilterchain)
结构图。

![number 1]({icondir}/number_1.png)
当用户提交用户名和密码时，`UsernamePasswordAuthenticationFilter` 从
`HttpServletRequest` 实例中提取用户名和密码，并创建一个
`UsernamePasswordAuthenticationToken`，这是一种
[`Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
类型的对象。

![number 2]({icondir}/number_2.png)
接着，`UsernamePasswordAuthenticationToken` 被传递给
`AuthenticationManager` 实例以完成认证。 `AuthenticationManager`
的具体实现取决于
[用户信息的存储方式](servlet/authentication/passwords/index.xml#servlet-authentication-unpwd-storage)。

![number 3]({icondir}/number_3.png) 如果认证失败，则进入 *失败处理*
流程：

1.  [SecurityContextHolder](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
    被清除。

2.  调用 `RememberMeServices.loginFail` 方法。
    如果未配置"记住我"功能，此操作为空（no-op）。 参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/authentication/RememberMeServices.html\[`RememberMeServices`\]
    接口。

3.  调用 `AuthenticationFailureHandler`。 参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/authentication/AuthenticationFailureHandler.html\[`AuthenticationFailureHandler`\]
    类。

![number 4]({icondir}/number_4.png) 如果认证成功，则进入 *成功处理*
流程：

1.  `SessionAuthenticationStrategy` 被通知新登录事件。 参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/authentication/session/SessionAuthenticationStrategy.html\[`SessionAuthenticationStrategy`\]
    接口。

2.  将
    [Authentication](servlet/authentication/architecture.xml#servlet-authentication-authentication)
    对象设置到
    [SecurityContextHolder](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
    中。 参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/context/SecurityContextPersistenceFilter.html\[`SecurityContextPersistenceFilter`\]
    类。

3.  调用 `RememberMeServices.loginSuccess` 方法。
    如果未配置"记住我"功能，此操作为空（no-op）。 参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/authentication/RememberMeServices.html\[`RememberMeServices`\]
    接口。

4.  `ApplicationEventPublisher` 发布一个
    `InteractiveAuthenticationSuccessEvent` 事件。

5.  调用 `AuthenticationSuccessHandler`。通常这是一个
    `SimpleUrlAuthenticationSuccessHandler`，它会将用户重定向至之前由
    [`ExceptionTranslationFilter`](servlet/architecture.xml#servlet-exceptiontranslationfilter)
    在跳转到登录页时保存的原始请求地址。

默认情况下，Spring Security 的表单登录功能是启用的。
然而，一旦提供了任何基于 Servlet 的配置，就必须显式地启用表单登录。
以下示例展示了一个最小化的显式 Java 配置：

:::: example
::: title
表单登录
:::

Java

:   ``` java
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .formLogin(withDefaults());
        // ...
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->
        <form-login />
    </http>
    ```

Kotlin

:   ``` kotlin
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            formLogin { }
        }
        // ...
    }
    ```
::::

在上述配置中，Spring Security 会自动渲染一个默认的登录页面。
大多数生产级应用需要自定义登录表单。

以下配置演示了如何提供一个自定义的登录表单。

:::: example
::: title
自定义登录表单配置
:::

Java

:   ``` java
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );
        // ...
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->
        <intercept-url pattern="/login" access="permitAll" />
        <form-login login-page="/login" />
    </http>
    ```

Kotlin

:   ``` kotlin
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            formLogin {
                loginPage = "/login"
                permitAll()
            }
        }
        // ...
    }
    ```
::::

当在 Spring Security 配置中指定了登录页面时，你需要负责渲染该页面。
以下是一个 [Thymeleaf](https://www.thymeleaf.org/) 模板，生成符合
`/login` 登录页面要求的 HTML 表单：

:::: formalpara
::: title
登录表单 - src/main/resources/templates/login.html
:::

``` xml
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="https://www.thymeleaf.org">
    <head>
        <title>请登录</title>
    </head>
    <body>
        <h1>请登录</h1>
        <div th:if="${param.error}">
            用户名或密码无效。</div>
        <div th:if="${param.logout}">
            您已成功退出登录。</div>
        <form th:action="@{/login}" method="post">
            <div>
                <input type="text" name="username" placeholder="用户名"/>
            </div>
            <div>
                <input type="password" name="password" placeholder="密码"/>
            </div>
            <input type="submit" value="登录" />
        </form>
    </body>
</html>
```
::::

关于默认 HTML 表单有几个关键点：

- 表单应使用 `POST` 方法提交到 `/login`。

- 表单需要包含一个 [CSRF
  Token](servlet/exploits/csrf.xml#servlet-csrf)，Thymeleaf
  会自动将其包含在内（[自动包含](servlet/exploits/csrf.xml#csrf-integration-form)）。

- 表单中用户名字段的参数名应为 `username`。

- 表单中密码字段的参数名应为 `password`。

- 如果 URL 中存在名为 `error` 的 HTTP
  参数，则表示用户提供的用户名或密码无效。

- 如果 URL 中存在名为 `logout` 的 HTTP 参数，则表示用户已成功登出。

许多用户的需求仅限于自定义登录页面。
但如有需要，您可以通过额外的配置来自定义上述所有行为。

如果您使用的是 Spring MVC，您需要一个控制器来将 `GET /login`
请求映射到我们创建的登录模板。 以下示例展示了一个最简化的
`LoginController`：

:::: example
::: title
LoginController
:::

Java

:   ``` java
    @Controller
    class LoginController {
        @GetMapping("/login")
        String login() {
            return "login";
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Controller
    class LoginController {
        @GetMapping("/login")
        fun login(): String {
            return "login"
        }
    }
    ```
::::
