Spring Security 允许您在请求级别上
[建模您的授权规则](servlet/authorization/index.xml)。例如，使用 Spring
Security 时，您可以指定所有 `/admin`
下的页面需要一种权限，而其他所有页面只需要身份验证即可。

默认情况下，Spring Security
要求每个请求都必须经过身份验证。然而，每次使用 [`HttpSecurity`
实例](servlet/configuration/java.xml#jc-httpsecurity)
时，都需要声明您的授权规则。

每当您有一个 `HttpSecurity` 实例时，至少应执行以下操作：

:::: example
::: title
使用 authorizeHttpRequests
:::

Java

:   ``` java
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated()
        )
    ```

Kotlin

:   ``` kotlin
    http {
        authorizeHttpRequests {
            authorize(anyRequest, authenticated)
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-url pattern="/**" access="authenticated"/>
    </http>
    ```
::::

这告诉 Spring
Security，应用程序中的任何端点都要求安全上下文至少通过身份验证才能允许访问。

在许多情况下，您的授权规则会比上述更复杂，因此请考虑以下使用场景：

- 我有一个使用 `authorizeRequests` 的应用，我想将其 [迁移到
  `authorizeHttpRequests`](#migrate-authorize-requests)

- 我想了解 [`AuthorizationFilter`
  组件的工作原理](#request-authorization-architecture)

- 我希望根据模式（特别是
  [正则表达式](#match-by-regex)）[匹配请求](#match-requests)

- 我希望匹配请求，并且我将 Spring MVC 映射到[非默认 Servlet
  的路径](#mvc-not-default-servlet)

- 我希望[授权请求](#authorize-requests)

- 我希望[以编程方式匹配请求](#match-by-custom)

- 我希望[以编程方式授权请求](#authorize-requests)

- 我希望[将请求授权委托给策略代理](#remote-authorization-manager)

# 理解请求授权组件的工作机制 {#request-authorization-architecture}

:::: note
::: title
:::

本节深入探讨了基于 Servlet 的应用中
[授权](servlet/authorization/index.xml#servlet-authorization)
在请求级别的工作方式，是对 [Servlet
架构和实现](servlet/architecture.xml#servlet-architecture)
的进一步扩展。
::::

<figure>
<img src="servlet/authorization/authorizationfilter.png"
alt="authorizationfilter" />
<figcaption>授权 HttpServletRequest</figcaption>
</figure>

- ![number 1]({icondir}/number_1.png) 首先，`AuthorizationFilter`
  构造一个 `Supplier`，该 `Supplier` 从
  [SecurityContextHolder](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
  中获取
  [Authentication](servlet/authentication/architecture.xml#servlet-authentication-authentication)。

- ![number 2]({icondir}/number_2.png) 其次，它将
  `Supplier<Authentication>` 和 `HttpServletRequest` 传递给
  [`AuthorizationManager`](servlet/architecture.xml#authz-authorization-manager)。`AuthorizationManager`
  将请求与 `authorizeHttpRequests` 中的模式进行匹配，并运行相应的规则。

  - ![number 3]({icondir}/number_3.png) 如果授权被拒绝，则 [发布
    `AuthorizationDeniedEvent`](servlet/authorization/events.xml) 并抛出
    `AccessDeniedException`。在这种情况下，[`ExceptionTranslationFilter`](servlet/architecture.xml#servlet-exceptiontranslationfilter)
    处理 `AccessDeniedException`。

  - ![number 4]({icondir}/number_4.png) 如果访问被授予，则 [发布
    `AuthorizationGrantedEvent`](servlet/authorization/events.xml)，并且
    `AuthorizationFilter` 继续执行
    [FilterChain](servlet/architecture.xml#servlet-filters-review)，从而允许应用程序正常处理。

## 默认情况下 `AuthorizationFilter` 位于最后 {#_默认情况下_authorizationfilter_位于最后}

`AuthorizationFilter` 默认位于 [Spring Security
过滤器链](servlet/architecture.xml#servlet-filterchain-figure)
的末尾。这意味着 Spring Security 的
[身份验证过滤器](servlet/authentication/index.xml)、[漏洞防护](servlet/exploits/index.xml)
和其他过滤器集成不需要授权。如果您在 `AuthorizationFilter`
之前添加自己的过滤器，它们也不需要授权；否则，它们就需要。

这种情况通常在添加
{spring-framework-reference-url}web.html#spring-web\[Spring MVC\]
端点时变得重要。因为它们由
{spring-framework-reference-url}web.html#mvc-servlet\[`DispatcherServlet`\]
执行，而这发生在 `AuthorizationFilter` 之后，所以您的端点需要被包含在
`authorizeHttpRequests` 中才能获得许可。

## 所有分发均需授权 {#_所有分发均需授权}

`AuthorizationFilter`
不仅在每个请求上运行，而且在每次分发（dispatch）上都会运行。这意味着
`REQUEST` 分发需要授权，同时 `FORWARD`、`ERROR` 和 `INCLUDE`
分发也需要授权。

例如，{spring-framework-reference-url}web.html#spring-web\[Spring MVC\]
可以将请求 `FORWARD` 到视图解析器来渲染 Thymeleaf 模板，如下所示：

:::: example
::: title
示例转发 Spring MVC 控制器
:::

Java

:   ``` java
    @Controller
    public class MyController {
        @GetMapping("/endpoint")
        public String endpoint() {
            return "endpoint";
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Controller
    class MyController {
        @GetMapping("/endpoint")
        fun endpoint(): String {
            return "endpoint"
        }
    }
    ```
::::

在这种情况下，授权会发生两次：一次是授权 `/endpoint`，另一次是转发到
Thymeleaf 渲染 \"endpoint\" 模板。

因此，您可能希望 [允许所有 `FORWARD` 分发](#match-by-dispatcher-type)。

另一个例子是
{spring-boot-reference-url}web.html#web.servlet.spring-mvc.error-handling\[Spring
Boot 如何处理错误\]。如果容器捕获到异常，比如下面这样：

:::: example
::: title
示例报错的 Spring MVC 控制器
:::

Java

:   ``` java
    @Controller
    public class MyController {
        @GetMapping("/endpoint")
        public String endpoint() {
            throw new UnsupportedOperationException("unsupported");
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Controller
    class MyController {
        @GetMapping("/endpoint")
        fun endpoint(): String {
            throw UnsupportedOperationException("unsupported")
        }
    }
    ```
::::

那么 Boot 会将其分发到 `ERROR` 分发。

在这种情况下，授权也会发生两次：一次是授权
`/endpoint`，另一次是分发错误。

因此，您可能希望 [允许所有 `ERROR` 分发](#match-by-dispatcher-type)。

## 延迟查找 `Authentication` {#_延迟查找_authentication}

记住，[`AuthorizationManager` API 使用
`Supplier<Authentication>`](servlet/authorization/architecture.xml#_the_authorizationmanager)。

当请求被[始终允许或始终拒绝](#authorize-requests)时，这对
`authorizeHttpRequests`
很重要。在这种情况下，[`Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
不会被查询，从而使请求更快。

# 授权端点 {#authorizing-endpoints}

您可以通过按优先级顺序添加更多规则来配置 Spring Security
以拥有不同的规则。

如果您希望仅允许具有 `USER` 权限的最终用户访问
`/endpoint`，则可以这样做：

:::: example
::: title
授权端点
:::

Java

:   ``` java
    @Bean
    public SecurityFilterChain web(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers("/endpoint").hasAuthority("USER")
                .anyRequest().authenticated()
            )
            // ...

        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun web(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize("/endpoint", hasAuthority("USER"))
                authorize(anyRequest, authenticated)
            }
        }

        return http.build()
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-url pattern="/endpoint" access="hasAuthority('USER')"/>
        <intercept-url pattern="/**" access="authenticated"/>
    </http>
    ```
::::

如您所见，声明可以分为模式/规则对。

`AuthorizationFilter`
按列出的顺序处理这些对，仅将第一个匹配项应用于请求。这意味着即使 `/**`
也能匹配 `/endpoint`，但上述规则没有问题。上述规则的含义是："如果请求是
`/endpoint`，则需要 `USER` 权限；否则，只需身份验证"。

Spring Security
支持多种模式和多种规则；您也可以以编程方式创建自己的模式和规则。

授权后，您可以使用 [Security
的测试支持](servlet/test/method.xml#test-method-withmockuser)
进行如下测试：

:::: example
::: title
测试端点授权
:::

Java

:   ``` java
    @WithMockUser(authorities="USER")
    @Test
    void endpointWhenUserAuthorityThenAuthorized() {
        this.mvc.perform(get("/endpoint"))
            .andExpect(status().isOk());
    }

    @WithMockUser
    @Test
    void endpointWhenNotUserAuthorityThenForbidden() {
        this.mvc.perform(get("/endpoint"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anyWhenUnauthenticatedThenUnauthorized() {
        this.mvc.perform(get("/any"))
            .andExpect(status().isUnauthorized());
    }
    ```
::::

# 匹配请求 {#match-requests}

上面您已经看到了 [两种匹配请求的方式](#authorizing-endpoints)。

第一种是最简单的，即匹配任何请求。

第二种是根据 URI 模式匹配。Spring Security 支持两种用于 URI
模式匹配的语言：[Ant](#match-by-ant)（如上所示）和
[正则表达式](#match-by-regex)。

## 使用 Ant 匹配 {#match-by-ant}

Ant 是 Spring Security 用来匹配请求的默认语言。

您可以使用它来匹配单个端点或目录，甚至可以捕获占位符供以后使用。您还可以将其细化为匹配特定的
HTTP 方法集。

假设您不想匹配 `/endpoint` 端点，而是想匹配 `/resource`
目录下的所有端点。在这种情况下，您可以这样做：

:::: example
::: title
Ant 匹配
:::

Java

:   ``` java
    http
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers("/resource/**").hasAuthority("USER")
            .anyRequest().authenticated()
        )
    ```

Kotlin

:   ``` kotlin
    http {
        authorizeHttpRequests {
            authorize("/resource/**", hasAuthority("USER"))
            authorize(anyRequest, authenticated)
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-url pattern="/resource/**" access="hasAuthority('USER')"/>
        <intercept-url pattern="/**" access="authenticated"/>
    </http>
    ```
::::

这句话的意思是："如果请求是 `/resource` 或其子目录，则需要 `USER`
权限；否则，只需身份验证。"

您还可以从请求中提取路径值，如下所示：

:::: example
::: title
授权并提取
:::

Java

:   ``` java
    http
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers("/resource/{name}").access(new WebExpressionAuthorizationManager("#name == authentication.name"))
            .anyRequest().authenticated()
        )
    ```

Kotlin

:   ``` kotlin
    http {
        authorizeHttpRequests {
            authorize("/resource/{name}", WebExpressionAuthorizationManager("#name == authentication.name"))
            authorize(anyRequest, authenticated)
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-url pattern="/resource/{name}" access="#name == authentication.name"/>
        <intercept-url pattern="/**" access="authenticated"/>
    </http>
    ```
::::

授权后，您可以使用 [Security
的测试支持](servlet/test/method.xml#test-method-withmockuser)
进行如下测试：

:::: example
::: title
测试目录授权
:::

Java

:   ``` java
    @WithMockUser(authorities="USER")
    @Test
    void endpointWhenUserAuthorityThenAuthorized() {
        this.mvc.perform(get("/endpoint/jon"))
            .andExpect(status().isOk());
    }

    @WithMockUser
    @Test
    void endpointWhenNotUserAuthorityThenForbidden() {
        this.mvc.perform(get("/endpoint/jon"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anyWhenUnauthenticatedThenUnauthorized() {
        this.mvc.perform(get("/any"))
            .andExpect(status().isUnauthorized());
    }
    ```
::::

:::: note
::: title
:::

Spring Security
仅匹配路径。如果您想匹配查询参数，则需要自定义请求匹配器。
::::

## 使用正则表达式匹配 {#match-by-regex}

Spring Security 支持将请求与正则表达式进行匹配。如果您想对子目录应用比
`**` 更严格的匹配标准，这可能会很有用。

例如，考虑一个包含用户名的路径，且所有用户名必须是字母数字的规则。您可以使用
{security-api-url}org/springframework/security/web/util/matcher/RegexRequestMatcher.html\[`RegexRequestMatcher`\]
来遵守此规则，如下所示：

:::: example
::: title
正则表达式匹配
:::

Java

:   ``` java
    http
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers(RegexRequestMatcher.regexMatcher("/resource/[A-Za-z0-9]+")).hasAuthority("USER")
            .anyRequest().denyAll()
        )
    ```

Kotlin

:   ``` kotlin
    http {
        authorizeHttpRequests {
            authorize(RegexRequestMatcher.regexMatcher("/resource/[A-Za-z0-9]+"), hasAuthority("USER"))
            authorize(anyRequest, denyAll)
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-url request-matcher="regex" pattern="/resource/[A-Za-z0-9]+" access="hasAuthority('USER')"/>
        <intercept-url pattern="/**" access="denyAll"/>
    </http>
    ```
::::

## 按 HTTP 方法匹配 {#match-by-httpmethod}

您还可以按 HTTP
方法匹配规则。一个有用的地方是在按授予的权限进行授权时，比如被授予
`read` 或 `write` 权限。

要要求所有 `GET` 请求具有 `read` 权限，所有 `POST` 请求具有 `write`
权限，您可以这样做：

:::: example
::: title
按 HTTP 方法匹配
:::

Java

:   ``` java
    http
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers(HttpMethod.GET).hasAuthority("read")
            .requestMatchers(HttpMethod.POST).hasAuthority("write")
            .anyRequest().denyAll()
        )
    ```

Kotlin

:   ``` kotlin
    http {
        authorizeHttpRequests {
            authorize(HttpMethod.GET, hasAuthority("read"))
            authorize(HttpMethod.POST, hasAuthority("write"))
            authorize(anyRequest, denyAll)
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-url http-method="GET" pattern="/**" access="hasAuthority('read')"/>
        <intercept-url http-method="POST" pattern="/**" access="hasAuthority('write')"/>
        <intercept-url pattern="/**" access="denyAll"/>
    </http>
    ```
::::

这些授权规则应理解为："如果请求是 GET，则需要 `read`
权限；否则，如果请求是 POST，则需要 `write` 权限；否则，拒绝请求。"

:::: tip
::: title
:::

默认拒绝请求是一种健康的安全部署实践，因为它将规则集转换为白名单。
::::

授权后，您可以使用 [Security
的测试支持](servlet/test/method.xml#test-method-withmockuser)
进行如下测试：

:::: example
::: title
测试 HTTP 方法授权
:::

Java

:   ``` java
    @WithMockUser(authorities="read")
    @Test
    void getWhenReadAuthorityThenAuthorized() {
        this.mvc.perform(get("/any"))
            .andExpect(status().isOk());
    }

    @WithMockUser
    @Test
    void getWhenNoReadAuthorityThenForbidden() {
        this.mvc.perform(get("/any"))
            .andExpect(status().isForbidden());
    }

    @WithMockUser(authorities="write")
    @Test
    void postWhenWriteAuthorityThenAuthorized() {
        this.mvc.perform(post("/any").with(csrf()))
            .andExpect(status().isOk());
    }

    @WithMockUser(authorities="read")
    @Test
    void postWhenNoWriteAuthorityThenForbidden() {
        this.mvc.perform(get("/any").with(csrf()))
            .andExpect(status().isForbidden());
    }
    ```
::::

## 按 Dispatcher 类型匹配 {#match-by-dispatcher-type}

:::: note
::: title
:::

此功能目前不支持 XML
::::

如前所述，Spring Security [默认会对所有 dispatcher
类型进行授权](#_all_dispatches_are_authorized)。尽管在 `REQUEST`
分发期间建立的
[安全上下文](servlet/authentication/architecture.xml#servlet-authentication-securitycontext)
会延续到后续分发，但细微的不匹配有时仍会导致意外的
`AccessDeniedException`。

为解决此问题，您可以配置 Spring Security Java 配置以允许 `FORWARD` 和
`ERROR` 等 dispatcher 类型，如下所示：

:::::::: example
::: title
按 Dispatcher 类型匹配
:::

:::: formalpara
::: title
Java
:::

``` java
http
    .authorizeHttpRequests((authorize) -> authorize
        .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
        .requestMatchers("/endpoint").permitAll()
        .anyRequest().denyAll()
    )
```
::::

:::: formalpara
::: title
Kotlin
:::

``` kotlin
http {
    authorizeHttpRequests {
        authorize(DispatcherTypeRequestMatcher(DispatcherType.FORWARD), permitAll)
        authorize(DispatcherTypeRequestMatcher(DispatcherType.ERROR), permitAll)
        authorize("/endpoint", permitAll)
        authorize(anyRequest, denyAll)
    }
}
```
::::
::::::::

## 使用 MvcRequestMatcher {#match-by-mvc}

通常，您可以像上面演示的那样使用 `requestMatchers(String)`。

但是，如果将 Spring MVC 映射到不同的 servlet
路径，则需要在安全配置中考虑这一点。

例如，如果 Spring MVC 被映射到 `/spring-mvc` 而不是
`/`（默认），那么您可能有一个类似 `/spring-mvc/my/controller`
的端点需要授权。

您需要使用 `MvcRequestMatcher` 将 servlet
路径和控制器路径在配置中分开，如下所示：

:::::::::: example
::: title
使用 MvcRequestMatcher 匹配
:::

:::: formalpara
::: title
Java
:::

``` java
@Bean
MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
    return new MvcRequestMatcher.Builder(introspector).servletPath("/spring-mvc");
}

@Bean
SecurityFilterChain appEndpoints(HttpSecurity http, MvcRequestMatcher.Builder mvc) {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers(mvc.pattern("/my/controller/**")).hasAuthority("controller")
            .anyRequest().authenticated()
        );

    return http.build();
}
```
::::

:::: formalpara
::: title
Kotlin
:::

``` kotlin
@Bean
fun mvc(introspector: HandlerMappingIntrospector): MvcRequestMatcher.Builder =
    MvcRequestMatcher.Builder(introspector).servletPath("/spring-mvc");

@Bean
fun appEndpoints(http: HttpSecurity, mvc: MvcRequestMatcher.Builder): SecurityFilterChain =
    http {
        authorizeHttpRequests {
            authorize(mvc.pattern("/my/controller/**"), hasAuthority("controller"))
            authorize(anyRequest, authenticated)
        }
    }
```
::::

:::: formalpara
::: title
Xml
:::

``` xml
<http>
    <intercept-url servlet-path="/spring-mvc" pattern="/my/controller/**" access="hasAuthority('controller')"/>
    <intercept-url pattern="/**" access="authenticated"/>
</http>
```
::::
::::::::::

这种需求至少可以通过两种不同方式产生：

- 如果您使用 `spring.mvc.servlet.path` Boot 属性将默认路径 (`/`)
  更改为其他内容

- 如果您注册了多个 Spring MVC
  `DispatcherServlet`（因此需要其中一个不是默认路径）

## 使用自定义匹配器 {#match-by-custom}

:::: note
::: title
:::

此功能目前不支持 XML
::::

在 Java 配置中，您可以创建自己的
{security-api-url}org/springframework/security/web/util/matcher/RequestMatcher.html\[`RequestMatcher`\]
并将其提供给 DSL，如下所示：

:::::::: example
::: title
按 Dispatcher 类型授权
:::

:::: formalpara
::: title
Java
:::

``` java
RequestMatcher printview = (request) -> request.getParameter("print") != null;
http
    .authorizeHttpRequests((authorize) -> authorize
        .requestMatchers(printview).hasAuthority("print")
        .anyRequest().authenticated()
    )
```
::::

:::: formalpara
::: title
Kotlin
:::

``` kotlin
val printview: RequestMatcher = { (request) -> request.getParameter("print") != null }
http {
    authorizeHttpRequests {
        authorize(printview, hasAuthority("print"))
        authorize(anyRequest, authenticated)
    }
}
```
::::
::::::::

:::: tip
::: title
:::

由于
{security-api-url}org/springframework/security/web/util/matcher/RequestMatcher.html\[`RequestMatcher`\]
是一个函数式接口，您可以在 DSL 中将其作为 lambda
提供。但是，如果您想从请求中提取值，则需要一个具体类，因为这需要重写
`default` 方法。
::::

授权后，您可以使用 [Security
的测试支持](servlet/test/method.xml#test-method-withmockuser)
进行如下测试：

:::: example
::: title
测试自定义授权
:::

Java

:   ``` java
    @WithMockUser(authorities="print")
    @Test
    void printWhenPrintAuthorityThenAuthorized() {
        this.mvc.perform(get("/any?print"))
            .andExpect(status().isOk());
    }

    @WithMockUser
    @Test
    void printWhenNoPrintAuthorityThenForbidden() {
        this.mvc.perform(get("/any?print"))
            .andExpect(status().isForbidden());
    }
    ```
::::

# 授权请求 {#authorize-requests}

一旦请求被匹配，您就可以通过几种方式对其进行授权
[已经见过](#match-requests)，例如 `permitAll`、`denyAll` 和
`hasAuthority`。

简而言之，以下是 DSL 中内置的授权规则：

- `permitAll` -
  请求不需要授权，是一个公共端点；注意在这种情况下，[不会从会话中检索
  `Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)

- `denyAll` -
  请求在任何情况下都不允许；注意在这种情况下，`Authentication`
  也不会从会话中检索

- `hasAuthority` - 请求要求 `Authentication` 具有与给定值匹配的
  [`GrantedAuthority`](servlet/authorization/architecture.xml#authz-authorities)

- `hasRole` - `hasAuthority` 的快捷方式，会自动添加 `ROLE_`
  前缀或配置的默认前缀

- `hasAnyAuthority` - 请求要求 `Authentication` 具有与任一给定值匹配的
  `GrantedAuthority`

- `hasAnyRole` - `hasAnyAuthority` 的快捷方式，会自动添加 `ROLE_`
  前缀或配置的默认前缀

- `access` - 请求使用此自定义 `AuthorizationManager` 来确定访问权限

现在您已经学习了模式、规则以及它们如何组合在一起，您应该能够理解这个更复杂的示例中发生了什么：

:::: example
::: title
授权请求
:::

Java

:   ``` java
    import static jakarta.servlet.DispatcherType.*;

    import static org.springframework.security.authorization.AuthorizationManagers.allOf;
    import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
    import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http
            // ...
            .authorizeHttpRequests(authorize -> authorize                                  
                .dispatcherTypeMatchers(FORWARD, ERROR).permitAll() 
                .requestMatchers("/static/**", "/signup", "/about").permitAll()         
                .requestMatchers("/admin/**").hasRole("ADMIN")                             
                .requestMatchers("/db/**").access(allOf(hasAuthority("db"), hasRole("ADMIN")))   
                .anyRequest().denyAll()                                                
            );

        return http.build();
    }
    ```
::::

- 指定了多个授权规则。每个规则按声明顺序考虑。

- 允许 `FORWARD` 和 `ERROR` 分发，以便
  {spring-framework-reference-url}web.html#spring-web\[Spring MVC\]
  可以渲染视图，Spring Boot 可以渲染错误

- 指定了多个任何用户都可以访问的 URL 模式。具体来说，如果 URL 以
  \"/static/\" 开头，等于 \"/signup\" 或等于
  \"/about\"，任何用户都可以访问该请求。

- 以 \"/admin/\" 开头的任何 URL 将限制给具有 \"ROLE_ADMIN\"
  角色的用户。请注意，由于我们调用了 `hasRole` 方法，因此无需指定
  \"ROLE\_\" 前缀。

- 以 \"/db/\" 开头的任何 URL 要求用户同时被授予 \"db\" 权限并且是
  \"ROLE_ADMIN\" 角色。请注意，由于我们使用的是 `hasRole`
  表达式，因此无需指定 \"ROLE\_\" 前缀。

- 未匹配的任何 URL
  都拒绝访问。如果您不想意外忘记更新授权规则，这是一个好策略。

# 使用 SpEL 表达授权 {#authorization-expressions}

虽然推荐使用具体的
`AuthorizationManager`，但在某些情况下表达式是必要的，比如使用
`<intercept-url>` 或 JSP
标签库时。因此，本节将重点介绍来自这些领域的示例。

鉴于此，让我们更深入地了解一下 Spring Security 的 Web 安全授权 SpEL
API。

Spring Security
将其所有授权字段和方法封装在一组根对象中。最通用的根对象称为
`SecurityExpressionRoot`，它是 `WebSecurityExpressionRoot`
的基础。Spring Security 在准备评估授权表达式时会将此根对象提供给
`StandardEvaluationContext`。

## 使用授权表达式字段和方法 {#using-authorization-expression-fields-and-methods}

首先，这为您的 SpEL
表达式提供了增强的一组授权字段和方法。以下是常见方法的快速概述：

- `permitAll` - 请求调用不需要授权；注意在这种情况下，[不会从会话中检索
  `Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)

- `denyAll` -
  请求在任何情况下都不允许；注意在这种情况下，`Authentication`
  也不会从会话中检索

- `hasAuthority` - 请求要求 `Authentication` 具有与给定值匹配的
  [`GrantedAuthority`](servlet/authorization/architecture.xml#authz-authorities)

- `hasRole` - `hasAuthority` 的快捷方式，会自动添加 `ROLE_`
  前缀或配置的默认前缀

- `hasAnyAuthority` - 请求要求 `Authentication` 具有与任一给定值匹配的
  `GrantedAuthority`

- `hasAnyRole` - `hasAnyAuthority` 的快捷方式，会自动添加 `ROLE_`
  前缀或配置的默认前缀

- `hasPermission` - 钩入您的 `PermissionEvaluator` 实例以进行对象级授权

以下是常见字段的简要说明：

- `authentication` - 与此方法调用关联的 `Authentication` 实例

- `principal` - 与此方法调用关联的 `Authentication#getPrincipal`

现在您已经学习了模式、规则以及它们如何组合在一起，您应该能够理解这个更复杂的示例中发生了什么：

:::: example
::: title
使用 SpEL 授权请求
:::

Xml

:   ``` java
    <http>
        <intercept-url pattern="/static/**" access="permitAll"/> 
        <intercept-url pattern="/admin/**" access="hasRole('ADMIN')"/> 
        <intercept-url pattern="/db/**" access="hasAuthority('db') and hasRole('ADMIN')"/> 
        <intercept-url pattern="/**" access="denyAll"/> 
    </http>
    ```
::::

- 指定了任何用户都可以访问的 URL 模式。具体来说，如果 URL 以
  \"/static/\" 开头，任何用户都可以访问该请求。

- 以 \"/admin/\" 开头的任何 URL 将限制给具有 \"ROLE_ADMIN\"
  角色的用户。请注意，由于我们调用了 `hasRole` 方法，因此无需指定
  \"ROLE\_\" 前缀。

- 以 \"/db/\" 开头的任何 URL 要求用户同时被授予 \"db\" 权限并且是
  \"ROLE_ADMIN\" 角色。请注意，由于我们使用的是 `hasRole`
  表达式，因此无需指定 \"ROLE\_\" 前缀。

- 未匹配的任何 URL
  都拒绝访问。如果您不想意外忘记更新授权规则，这是一个好策略。

## 使用路径参数 {#using_path_parameters}

此外，Spring Security 提供了一种发现路径参数的机制，以便它们也可以在
SpEL 表达式中访问。

例如，您可以通过以下方式在 SpEL 表达式中访问路径参数：

:::: example
::: title
使用 SpEL 路径变量授权请求
:::

Xml

:   ``` xml
    <http>
        <intercept-url pattern="/resource/{name}" access="#name == authentication.name"/>
        <intercept-url pattern="/**" access="authenticated"/>
    </http>
    ```
::::

此表达式引用 `/resource/` 后的路径变量，并要求其等于
`Authentication#getName`。

## 使用授权数据库、策略代理或其他服务 {#remote-authorization-manager}

如果您希望配置 Spring Security 使用单独的服务进行授权，可以创建自己的
`AuthorizationManager` 并将其匹配到 `anyRequest`。

首先，您的 `AuthorizationManager` 可能看起来像这样：

:::: example
::: title
Open Policy Agent 授权管理器
:::

Java

:   ``` java
    @Component
    public final class OpenPolicyAgentAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
            // 向 Open Policy Agent 发送请求
        }
    }
    ```
::::

然后，您可以如下将其集成到 Spring Security 中：

:::: example
::: title
所有请求都转到远程服务
:::

Java

:   ``` java
    @Bean
    SecurityFilterChain web(HttpSecurity http, AuthorizationManager<RequestAuthorizationContext> authz) throws Exception {
        http
            // ...
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().access(authz)
            );

        return http.build();
    }
    ```
::::

## 偏好使用 `permitAll` 而不是 `ignoring` {#favor-permitall}

当您有静态资源时，可能会倾向于配置过滤器链以忽略这些值。更安全的方法是使用
`permitAll` 来允许它们，如下所示：

:::::::: example
::: title
允许静态资源
:::

:::: formalpara
::: title
Java
:::

``` java
http
    .authorizeHttpRequests((authorize) -> authorize
        .requestMatchers("/css/**").permitAll()
        .anyRequest().authenticated()
    )
```
::::

:::: formalpara
::: title
Kotlin
:::

``` kotlin
http {
    authorizeHttpRequests {
        authorize("/css/**", permitAll)
        authorize(anyRequest, authenticated)
    }
}
```
::::
::::::::

这种方法更安全，因为即使是静态资源，编写安全头也很重要，而如果请求被忽略，Spring
Security 就无法做到这一点。

在过去，这带来了性能权衡，因为 Spring Security
会在每个请求上查询会话。但从 Spring Security 6
开始，除非授权规则需要，否则不再查询会话。由于现在已解决了性能影响，Spring
Security 建议至少对所有请求使用 `permitAll`。

# 从 `authorizeRequests` 迁移 {#migrate-authorize-requests}

:::: note
::: title
:::

`AuthorizationFilter` 取代了
{security-api-url}org/springframework/security/web/access/intercept/FilterSecurityInterceptor.html\[`FilterSecurityInterceptor`\]。为了保持向后兼容性，`FilterSecurityInterceptor`
仍然是默认的。本节讨论 `AuthorizationFilter`
的工作原理以及如何覆盖默认配置。
::::

{security-api-url}org/springframework/security/web/access/intercept/AuthorizationFilter.html\[`AuthorizationFilter`\]
为 `HttpServletRequest`s 提供
[授权](servlet/authorization/index.xml#servlet-authorization)。它被插入到
[FilterChainProxy](servlet/architecture.xml#servlet-filterchainproxy)
中作为 [Security
Filters](servlet/architecture.xml#servlet-security-filters) 之一。

您可以在声明 `SecurityFilterChain` 时覆盖默认设置。不要使用
{security-api-url}org/springframework/security/config/annotation/web/builders/HttpSecurity.html#authorizeRequests()\[`authorizeRequests`\]，而是使用
`authorizeHttpRequests`，如下所示：

:::: example
::: title
使用 authorizeHttpRequests
:::

Java

:   ``` java
    @Bean
    SecurityFilterChain web(HttpSecurity http) throws AuthenticationException {
        http
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated();
            )
            // ...

        return http.build();
    }
    ```
::::

这在几个方面改进了 `authorizeRequests`：

1.  使用简化的 `AuthorizationManager`
    API，而不是元数据源、配置属性、决策管理器和投票者。这简化了重用和自定义。

2.  延迟 `Authentication`
    查找。不再需要为每个请求查找身份验证，只有在授权决策需要身份验证时才查找。

3.  支持基于 Bean 的配置。

当使用 `authorizeHttpRequests` 而不是 `authorizeRequests`
时，{security-api-url}org/springframework/security/web/access/intercept/AuthorizationFilter.html\[`AuthorizationFilter`\]
将取代
{security-api-url}org/springframework/security/web/access/intercept/FilterSecurityInterceptor.html\[`FilterSecurityInterceptor`\]。

## 迁移表达式 {#_迁移表达式}

尽可能推荐使用类型安全的授权管理器而不是 SpEL。对于 Java
配置，{security-api-url}org/springframework/security/web/access/expression/WebExpressionAuthorizationManager.html\[`WebExpressionAuthorizationManager`\]
可用于帮助迁移遗留的 SpEL。

要使用
`WebExpressionAuthorizationManager`，可以用您要迁移的表达式构造一个实例，如下所示：

::: informalexample

Java

:   ``` java
    .requestMatchers("/test/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') && hasRole('USER')"))
    ```

Kotlin

:   ``` kotlin
    .requestMatchers("/test/**").access(WebExpressionAuthorizationManager("hasRole('ADMIN') && hasRole('USER')"))
    ```
:::

如果您的表达式中引用了一个
bean，例如：`@webSecurity.check(authentication, request)`，建议直接调用该
bean，代码看起来像这样：

::: informalexample

Java

:   ``` java
    .requestMatchers("/test/**").access((authentication, context) ->
        new AuthorizationDecision(webSecurity.check(authentication.get(), context.getRequest())))
    ```

Kotlin

:   ``` kotlin
    .requestMatchers("/test/**").access((authentication, context): AuthorizationManager<RequestAuthorizationContext> ->
        AuthorizationDecision(webSecurity.check(authentication.get(), context.getRequest())))
    ```
:::

对于包含 bean 引用和其他表达式的复杂指令，建议将其改为实现
`AuthorizationManager` 并通过 `.access(AuthorizationManager)` 调用它们。

如果无法做到这一点，您可以配置一个
{security-api-url}org/springframework/security/web/access/expression/DefaultHttpSecurityExpressionHandler.html\[`DefaultHttpSecurityExpressionHandler`\]，并为其提供一个
bean 解析器，然后将其提供给
`WebExpressionAuthorizationManager#setExpressionhandler`。

# 安全匹配器 {#security-matchers}

{security-api-url}org/springframework/security/web/util/matcher/RequestMatcher.html\[`RequestMatcher`\]
接口用于确定请求是否符合给定规则。我们使用 `securityMatchers` 来确定
[给定的 `HttpSecurity`](servlet/configuration/java.xml#jc-httpsecurity)
是否应应用于给定请求。同样，我们可以使用 `requestMatchers`
来确定应应用于给定请求的授权规则。看以下示例：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .securityMatcher("/api/**")                            
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/api/user/**").hasRole("USER")   
                    .requestMatchers("/api/admin/**").hasRole("ADMIN") 
                    .anyRequest().authenticated()                      
                )
                .formLogin(withDefaults());
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    open class SecurityConfig {

        @Bean
        open fun web(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher("/api/**")                                           
                authorizeHttpRequests {
                    authorize("/api/user/**", hasRole("USER"))                       
                    authorize("/api/admin/**", hasRole("ADMIN"))                     
                    authorize(anyRequest, authenticated)                             
                }
            }
            return http.build()
        }

    }
    ```
:::

- 配置 `HttpSecurity` 仅应用于以 `/api/` 开头的 URL

- 允许具有 `USER` 角色的用户访问以 `/api/user/` 开头的 URL

- 允许具有 `ADMIN` 角色的用户访问以 `/api/admin/` 开头的 URL

- 不符合上述规则的任何其他请求都需要身份验证

`securityMatcher(s)` 和 `requestMatcher(s)` 方法将决定哪种
`RequestMatcher` 实现最适合您的应用：如果
{spring-framework-reference-url}web.html#spring-web\[Spring MVC\]
在类路径中，则使用
{security-api-url}org/springframework/security/web/servlet/util/matcher/MvcRequestMatcher.html\[`MvcRequestMatcher`\]，否则使用
{security-api-url}org/springframework/security/web/servlet/util/matcher/AntPathRequestMatcher.html\[`AntPathRequestMatcher`\]。您可以在此处阅读有关
Spring MVC 集成的更多信息 xref:servlet/integrations/mvc.adoc。

如果您想使用特定的 `RequestMatcher`，只需将其实现传递给
`securityMatcher` 和/或 `requestMatcher` 方法：

::: informalexample

Java

:   ``` java
    import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher; 
    import static org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher;

    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .securityMatcher(antMatcher("/api/**"))                              
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers(antMatcher("/api/user/**")).hasRole("USER")     
                    .requestMatchers(regexMatcher("/api/admin/.*")).hasRole("ADMIN") 
                    .requestMatchers(new MyCustomRequestMatcher()).hasRole("SUPERVISOR")     
                    .anyRequest().authenticated()
                )
                .formLogin(withDefaults());
            return http.build();
        }
    }

    public class MyCustomRequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            // ...
        }
    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher 
    import org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher

    @Configuration
    @EnableWebSecurity
    open class SecurityConfig {

        @Bean
        open fun web(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher(antMatcher("/api/**"))                               
                authorizeHttpRequests {
                    authorize(antMatcher("/api/user/**"), hasRole("USER"))           
                    authorize(regexMatcher("/api/admin/**"), hasRole("ADMIN"))       
                    authorize(MyCustomRequestMatcher(), hasRole("SUPERVISOR"))       
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }

    }
    ```
:::

- 导入 `AntPathRequestMatcher` 和 `RegexRequestMatcher`
  的静态工厂方法以创建 `RequestMatcher` 实例。

- 配置 `HttpSecurity` 仅应用于以 `/api/` 开头的 URL，使用
  `AntPathRequestMatcher`

- 允许具有 `USER` 角色的用户访问以 `/api/user/` 开头的 URL，使用
  `AntPathRequestMatcher`

- 允许具有 `ADMIN` 角色的用户访问以 `/api/admin/` 开头的 URL，使用
  `RegexRequestMatcher`

- 允许具有 `SUPERVISOR` 角色的用户访问符合 `MyCustomRequestMatcher` 的
  URL，使用自定义 `RequestMatcher`

# 进一步阅读 {#_进一步阅读}

现在您已经保护了应用程序的请求，可以考虑
[保护其方法](servlet/authorization/method-security.xml)。您还可以进一步阅读
[测试您的应用程序](servlet/test/index.xml) 或关于将 Spring Security
与其他应用程序方面集成的内容，例如
[数据层](servlet/integrations/data.xml) 或
[跟踪和指标](servlet/integrations/observability.xml)。
