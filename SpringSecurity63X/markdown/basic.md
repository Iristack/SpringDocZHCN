本节详细介绍 Spring Security 如何为基于 Servlet 的应用程序提供对 [HTTP
Basic 认证](https://tools.ietf.org/html/rfc7617) 的支持。

本节描述了 HTTP Basic 认证在 Spring Security 中的工作机制。
首先，当未认证的客户端访问资源时，服务器会返回一个
[WWW-Authenticate](https://tools.ietf.org/html/rfc7235#section-4.1)
响应头：

<figure>
<img
src="servlet/authentication/unpwd/basicauthenticationentrypoint.png"
alt="basicauthenticationentrypoint" />
<figcaption>发送 WWW-Authenticate 头部</figcaption>
</figure>

上图基于我们
[`SecurityFilterChain`](servlet/architecture.xml#servlet-securityfilterchain)
的结构图。

![number 1]({icondir}/number_1.png) 首先，用户向 `/private`
资源发起一个未经身份验证的请求，而该用户没有访问此资源的权限。

![number 2]({icondir}/number_2.png) Spring Security 的
[`AuthorizationFilter`](servlet/authorization/authorize-http-requests.xml)
判断该未认证请求为 *拒绝访问*，并抛出 `AccessDeniedException` 异常。

![number 3]({icondir}/number_3.png)
由于用户尚未认证，[`ExceptionTranslationFilter`](servlet/architecture.xml#servlet-exceptiontranslationfilter)
启动 *认证流程*。 此时配置的
[`AuthenticationEntryPoint`](servlet/authentication/architecture.xml#servlet-authentication-authenticationentrypoint)
是
{security-api-url}org/springframework/security/web/authentication/www/BasicAuthenticationEntryPoint.html\[`BasicAuthenticationEntryPoint`\]
实例，它负责发送 WWW-Authenticate 响应头。 `RequestCache` 通常是一个
`NullRequestCache`，不会缓存原始请求，因为客户端有能力重放其原始请求。

当客户端收到 `WWW-Authenticate`
头部后，便知道需要使用用户名和密码重新尝试请求。
下图展示了用户名和密码处理的流程：

<figure id="servlet-authentication-basicauthenticationfilter">
<img src="servlet/authentication/unpwd/basicauthenticationfilter.png"
alt="basicauthenticationfilter" />
<figcaption>认证用户名和密码</figcaption>
</figure>

上图同样基于我们的
[`SecurityFilterChain`](servlet/architecture.xml#servlet-securityfilterchain)
结构图。

![number 1]({icondir}/number_1.png)
当用户提交用户名和密码后，`BasicAuthenticationFilter` 从
`HttpServletRequest` 中提取用户名和密码，并创建一个
`UsernamePasswordAuthenticationToken`，这是
[`Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
接口的一种实现。

![number 2]({icondir}/number_2.png)
接着，`UsernamePasswordAuthenticationToken` 被传递给
`AuthenticationManager` 进行认证。 `AuthenticationManager`
的具体实现取决于
[用户信息的存储方式](servlet/authentication/passwords/index.xml#servlet-authentication-unpwd-storage)。

![number 3]({icondir}/number_3.png) 如果认证失败，则进入 *失败流程*：

1.  清除
    [SecurityContextHolder](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
    中的内容；

2.  调用 `RememberMeServices.loginFail`
    方法；如果未配置"记住我"功能，则此操作无效； 参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/authentication/RememberMeServices.html\[`RememberMeServices`\]
    接口；

3.  调用 `AuthenticationEntryPoint`，触发再次发送 WWW-Authenticate 头；
    参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/AuthenticationEntryPoint.html\[`AuthenticationEntryPoint`\]
    接口。

![number 4]({icondir}/number_4.png) 如果认证成功，则进入 *成功流程*：

1.  将认证成功的
    [Authentication](servlet/authentication/architecture.xml#servlet-authentication-authentication)
    对象设置到
    [SecurityContextHolder](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
    中；

2.  调用 `RememberMeServices.loginSuccess`
    方法；如果未配置"记住我"，则此操作无效； 参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/authentication/RememberMeServices.html\[`RememberMeServices`\]
    接口；

3.  `BasicAuthenticationFilter` 调用
    `FilterChain.doFilter(request, response)`，继续执行应用的其余逻辑；
    参见 Javadoc 中的
    {security-api-url}org/springframework/security/web/authentication/www/BasicAuthenticationFilter.html\[`BasicAuthenticationFilter`\]
    类。

默认情况下，Spring Security 的 HTTP Basic 认证是启用的。
但是，一旦提供了任何基于 Servlet 的安全配置，就必须显式地启用 HTTP Basic
认证。

以下示例展示了一个最小化的显式配置：

:::: example
::: title
显式的 HTTP Basic 配置
:::

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            // ...
            .httpBasic(withDefaults());
        return http.build();
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->
        <http-basic />
    </http>
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            // ...
            httpBasic { }
        }
        return http.build()
    }
    ```
::::
