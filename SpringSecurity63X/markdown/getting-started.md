本节介绍如何将 Spring Security 与 {spring-boot-reference-url}\[Spring
Boot\] 配合使用的最基本配置，并在之后指引你下一步的操作。

:::: note
::: title
:::

完整的入门应用可以在我们的示例仓库中找到：{gh-samples-url}/servlet/spring-boot/java/hello-security。
为方便起见，你可以下载一个由 Spring Initializr 准备的最小化 Spring
Boot + Spring Security
应用：https://start.spring.io/starter.zip?type=maven-project&language=java&packaging=jar&jvmVersion=1.8&groupId=example&artifactId=hello-security&name=hello-security&description=Hello%20Security&packageName=example.hello-security&dependencies=web,security。
::::

# 更新依赖项 {#servlet-hello-dependencies}

你需要首先将 Spring Security
添加到应用程序的类路径中；有两种方式可以实现这一点：使用
[Maven](getting-spring-security.xml#getting-maven-boot) 或
[Gradle](getting-spring-security.xml#getting-gradle-boot)。

# 启动 Hello Spring Security Boot {#servlet-hello-starting}

当 Spring Security 已 [位于类路径上](#servlet-hello-dependencies)
时，你现在可以运行
{spring-boot-reference-url}#using.running-your-application\[Spring Boot
应用程序\]。 以下片段展示了部分输出内容，表明 Spring Security
已在你的应用中启用：

:::: example
::: title
运行 Spring Boot 应用程序
:::

Maven

:   ``` bash
    $ ./mvnw spring-boot:run
    ...
    INFO 23689 --- [  restartedMain] .s.s.UserDetailsServiceAutoConfiguration :

    Using generated security password: 8e557245-73e2-4286-969a-ff57fe326336

    ...
    ```

Gradle

:   ``` bash
    $ ./gradlew :bootRun
    ...
    INFO 23689 --- [  restartedMain] .s.s.UserDetailsServiceAutoConfiguration :

    Using generated security password: 8e557245-73e2-4286-969a-ff57fe326336

    ...
    ```

Jar

:   ``` bash
    $ java -jar target/myapplication-0.0.1.jar
    ...
    INFO 23689 --- [  restartedMain] .s.s.UserDetailsServiceAutoConfiguration :

    Using generated security password: 8e557245-73e2-4286-969a-ff57fe326336

    ...
    ```
::::

现在你已经成功启动了应用，可以尝试访问某个端点来看看会发生什么。
如果你不带凭据地访问某个端点，例如：

:::: formalpara
::: title
查询受保护的 Boot 应用
:::

``` bash
$ curl -i http://localhost:8080/some/path
HTTP/1.1 401
...
```
::::

那么 Spring Security 将以 `401 Unauthorized` 拒绝访问。

:::: tip
::: title
:::

如果你在浏览器中输入相同的 URL，它将重定向到默认登录页面。
::::

而如果你使用凭据（可在控制台输出中找到）进行请求，如下所示：

:::: formalpara
::: title
使用凭据查询
:::

``` bash
$ curl -i -u user:8e557245-73e2-4286-969a-ff57fe326336 http://localhost:8080/some/path
HTTP/1.1 404
...
```
::::

则 Spring Boot 会处理该请求，但由于 `/some/path` 并不存在，因此返回
`404 Not Found`。

接下来，你可以选择：

- 更深入地了解 [Spring Boot 默认为 Spring Security
  启用了哪些功能](#servlet-hello-auto-configuration)

- 阅读有关 [Spring Security 支持的常见使用场景](#security-use-cases)

- 开始配置认证机制：[认证](servlet/authentication/index.xml)

# 运行时行为说明 {#servlet-hello-auto-configuration}

Spring Boot 和 Spring Security 的默认配置在运行时提供了以下行为：

- 要求对任意端点（包括 Boot 的 `/error` 端点）进行用户
  [身份验证](servlet/authorization/authorize-http-requests.xml)

- [注册一个默认用户](servlet/authentication/passwords/user-details-service.xml)，并在启动时生成密码（密码会输出到控制台；如上例中的
  `8e557245-73e2-4286-969a-ff57fe326336`）

- 使用 BCrypt 对
  [密码存储进行保护](servlet/authentication/passwords/password-encoder.xml)，并支持其他编码方式

- 提供基于表单的 [登录](servlet/authentication/passwords/form.xml) 和
  [注销](servlet/authentication/logout.xml) 流程

- 支持 [表单登录](servlet/authentication/passwords/form.xml) 和 [HTTP
  Basic 认证](servlet/authentication/passwords/basic.xml)

- 提供内容协商：对 Web 请求重定向到登录页；对服务请求返回
  `401 Unauthorized`

- [防范 CSRF](servlet/exploits/csrf.xml) 攻击

- [防范会话固定](servlet/authentication/session-management.xml#ns-session-fixation)
  攻击

- 写入
  [Strict-Transport-Security](servlet/exploits/headers.xml#servlet-headers-hsts)
  头部，确保使用 HTTPS

- 写入
  [X-Content-Type-Options](servlet/exploits/headers.xml#servlet-headers-content-type-options)
  头部，防止 [MIME
  类型嗅探攻击](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options)

- 写入
  [缓存控制头部](servlet/exploits/headers.xml#servlet-headers-cache-control)，以保护已认证资源

- 写入
  [X-Frame-Options](servlet/exploits/headers.xml#servlet-headers-frame-options)
  头部，防止
  [点击劫持攻击](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options)

- 与 [`HttpServletRequest`
  的认证方法](servlet/integrations/servlet-api.xml) 集成

- 发布 [认证成功和失败事件](servlet/authentication/events.xml)

理解 Spring Boot 是如何与 Spring Security 协作实现这些功能是有帮助的。
查看
{spring-boot-api-url}org/springframework/boot/autoconfigure/security/servlet/SecurityAutoConfiguration.html\[Boot
的安全自动配置\] 可知，其主要执行以下操作（简化以便说明）：

:::: formalpara
::: title
Spring Boot 安全自动配置
:::

``` java
@EnableWebSecurity 
@Configuration
public class DefaultSecurityConfig {
    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    InMemoryUserDetailsManager inMemoryUserDetailsManager() { 
        String generatedPassword = // ...;
        return new InMemoryUserDetailsManager(User.withUsername("user")
                .password(generatedPassword).roles("USER").build());
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationEventPublisher.class)
    DefaultAuthenticationEventPublisher defaultAuthenticationEventPublisher(ApplicationEventPublisher delegate) { 
        return new DefaultAuthenticationEventPublisher(delegate);
    }
}
```
::::

1.  添加 `@EnableWebSecurity` 注解。（这会发布 [Spring Security 默认的
    `Filter` 链](servlet/architecture.xml#servlet-securityfilterchain)
    作为一个 `@Bean`）

2.  发布一个
    [`UserDetailsService`](servlet/authentication/passwords/user-details-service.xml)
    `@Bean`，用户名为 `user`，密码是随机生成并打印到控制台的

3.  发布一个
    [`AuthenticationEventPublisher`](servlet/authentication/events.xml)
    `@Bean`，用于发布认证事件

:::: note
::: title
:::

Spring Boot 会将所有作为 `@Bean` 发布的 `Filter`
添加到应用的过滤器链中。这意味着，在 Spring Boot 中使用
`@EnableWebSecurity` 会自动为每个请求注册 Spring Security 的过滤器链。
::::

# 安全使用场景 {#security-use-cases}

从这里开始，你可能有多个方向可以选择。为了确定下一步对你和你的应用最合适的方向，请考虑以下
Spring Security 设计用于解决的常见使用场景：

- 我正在构建一个 REST API，需要 [验证
  JWT](servlet/oauth2/resource-server/jwt.xml) 或
  [其他承载令牌](servlet/oauth2/resource-server/opaque-token.xml)

- 我正在构建一个 Web 应用、API 网关或 BFF（Backend For
  Frontend），并且：

  - 需要通过 [OAuth 2.0 或 OIDC 登录](servlet/oauth2/login/core.xml)

  - 需要通过 [SAML 2.0 登录](servlet/saml2/login/index.xml)

  - 需要通过 [CAS 登录](servlet/authentication/cas.xml)

- 我需要管理：

  - 用户信息，存储于 [LDAP](servlet/authentication/passwords/ldap.xml)
    或 [Active
    Directory](servlet/authentication/passwords/ldap.xml#_active_directory)，或使用
    [Spring Data](servlet/integrations/data.xml)，或通过
    [JDBC](servlet/authentication/passwords/jdbc.xml)

  - [密码存储](servlet/authentication/passwords/storage.xml)

如果以上场景都不符合你的需求，建议按以下顺序思考你的应用：

1.  **协议**：首先考虑你的应用将使用的通信协议。对于基于 Servlet
    的应用，Spring Security 支持 HTTP 以及
    [WebSocket](servlet/integrations/websocket.xml)。

2.  **认证**：其次，考虑用户如何
    [进行认证](servlet/authentication/index.xml)，以及该认证是有状态还是无状态。

3.  **授权**：然后，考虑你将如何判断
    [用户被授权执行哪些操作](servlet/authorization/index.xml)。

4.  **防御**：最后，[集成 Spring Security
    的默认防护机制](servlet/exploits/csrf.xml#csrf-considerations)，并评估你还需要哪些
    [额外的安全防护措施](servlet/exploits/headers.xml)。
