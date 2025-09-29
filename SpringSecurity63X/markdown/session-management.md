一旦你的应用程序实现了
[请求认证](servlet/authentication/index.xml)，接下来重要的是考虑如何持久化这个认证结果，并在后续的请求中恢复它。

默认情况下，这一过程是自动完成的，因此无需额外编写代码。但了解
`HttpSecurity` 中 `requireExplicitSave` 的含义仍然很重要。

如果你感兴趣，可以 [深入了解 requireExplicitSave
的作用](#how-it-works-requireexplicitsave) 或
[为什么它如此重要](#requireexplicitsave)。否则，在大多数情况下，你已经完成了本节内容。

但在离开之前，请思考以下使用场景是否适用于你的应用：

- 我想
  [了解会话管理的组件](#understanding-session-management-components)

- 我想 [限制用户同时登录的次数](#ns-concurrent-sessions)

- 我想 [手动存储认证信息](#store-authentication-manually)，而不是让
  Spring Security 代劳

- 我正在手动存储认证信息，并希望
  [正确清除它](#properly-clearing-authentication)

- 我正在使用
  [`SessionManagementFilter`](#the-sessionmanagementfilter)，并需要
  [迁离该过滤器的指导](#moving-away-from-sessionmanagementfilter)

- 我想将认证信息
  [存储在除会话之外的地方](#customizing-where-authentication-is-stored)

- 我正在使用 [无状态认证](#stateless-authentication)，但
  [仍希望将其存储在会话中](#storing-stateless-authentication-in-the-session)

- 我使用了 `SessionCreationPolicy.NEVER`，但
  [应用程序仍在创建会话](#never-policy-session-still-created)。

# 理解会话管理的组件 {#understanding-session-management-components}

会话管理支持由几个协同工作的组件组成。这些组件包括
[`SecurityContextHolderFilter`](servlet/authentication/persistence.xml#securitycontextholderfilter)、[`SecurityContextPersistenceFilter`](servlet/authentication/persistence.xml#securitycontextpersistencefilter)
和 [`SessionManagementFilter`](#the-sessionmanagementfilter)。

:::: note
::: title
:::

在 Spring Security 6 中，默认不会设置 `SecurityContextPersistenceFilter`
和 `SessionManagementFilter`。 此外，任何应用程序都应仅设置
`SecurityContextHolderFilter` 或
`SecurityContextPersistenceFilter`，而不能同时设置两者。
::::

## `SessionManagementFilter` {#the-sessionmanagementfilter}

`SessionManagementFilter` 通过检查 `SecurityContextRepository`
的内容与当前 `SecurityContextHolder`
的内容来确定用户是否在当前请求期间已通过身份验证，通常是由非交互式身份验证机制（如预认证或"记住我"）完成的
[^1]。 如果仓库包含安全上下文，过滤器不做任何事情。
如果没有，并且线程本地的 `SecurityContext`
包含一个（非匿名的）`Authentication`
对象，过滤器会假定它们已被堆栈中的前一个过滤器进行了身份验证。
然后它将调用配置的 `SessionAuthenticationStrategy`。

如果用户当前未经过身份验证，过滤器将检查是否请求了一个无效的会话
ID（例如由于超时），并且如果设置了，则会调用配置的
`InvalidSessionStrategy`。 最常见的行为只是重定向到固定的
URL，这在标准实现 `SimpleRedirectInvalidSessionStrategy` 中得到了封装。
当通过命名空间配置无效会话 URL
时，也会使用后者，[如前所述](#session-mgmt)。

### 迁移远离 `SessionManagementFilter` {#moving-away-from-sessionmanagementfilter}

在 Spring Security 5 中，默认配置依赖于 `SessionManagementFilter`
来检测用户是否刚刚通过身份验证，并调用
{security-api-url}org/springframework/security/web/authentication/session/SessionAuthenticationStrategy.html\[`SessionAuthenticationStrategy`\]。
问题是这意味着在典型设置中，每个请求都必须读取 `HttpSession`。

在 Spring Security 6 中，默认情况是身份验证机制本身必须调用
`SessionAuthenticationStrategy`。 这意味着不需要检测何时完成
`Authentication`，因此不必为每个请求读取 `HttpSession`。

### 迁移远离 `SessionManagementFilter` 时需考虑的事项 {#_迁移远离_sessionmanagementfilter_时需考虑的事项}

在 Spring Security 6 中，默认不使用 `SessionManagementFilter`，因此
`sessionManagement` DSL 中的一些方法将不起作用。

+---------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| 方法                                  | 替代方案                                                                                                                               |
+=======================================+========================================================================================================================================+
| `sessionAuthenticationErrorUrl`       | 在你的身份验证机制中配置一个                                                                                                           |
|                                       | {security-api-url}/org/springframework/security/web/authentication/AuthenticationFailureHandler.html\[`AuthenticationFailureHandler`\] |
+---------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| `sessionAuthenticationFailureHandler` | 在你的身份验证机制中配置一个                                                                                                           |
|                                       | {security-api-url}/org/springframework/security/web/authentication/AuthenticationFailureHandler.html\[`AuthenticationFailureHandler`\] |
+---------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| `sessionAuthenticationStrategy`       | 在你的身份验证机制中配置一个 `SessionAuthenticationStrategy`，如上文 [所述](#moving-away-from-sessionmanagementfilter)                 |
+---------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------+

如果你尝试使用这些方法中的任何一个，将会抛出异常。

# 自定义认证信息的存储位置 {#customizing-where-authentication-is-stored}

默认情况下，Spring Security 会为你将在 HTTP
会话中存储安全上下文。然而，你可能有以下几个原因想要自定义这一点：

- 你可能想要调用 `HttpSessionSecurityContextRepository` 实例上的各个
  setter 方法

- 你可能想要将在缓存或数据库中存储安全上下文以实现水平扩展

首先，你需要创建一个 `SecurityContextRepository`
的实现，或者使用现有的实现如
`HttpSessionSecurityContextRepository`，然后可以在 `HttpSecurity`
中设置它。

:::: {#customizing-the-securitycontextrepository .example}
::: title
自定义 `SecurityContextRepository`
:::

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        SecurityContextRepository repo = new MyCustomSecurityContextRepository();
        http
            // ...
            .securityContext((context) -> context
                .securityContextRepository(repo)
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        val repo = MyCustomSecurityContextRepository()
        http {
            // ...
            securityContext {
                securityContextRepository = repo
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http security-context-repository-ref="repo">
        <!-- ... -->
    </http>
    <bean name="repo" class="com.example.MyCustomSecurityContextRepository" />
    ```
::::

:::: note
::: title
:::

上述配置将 `SecurityContextRepository` 设置在
`SecurityContextHolderFilter` 和 **参与**的身份验证过滤器（如
`UsernamePasswordAuthenticationFilter`）上。
若还需在无状态过滤器中设置，请参见 [如何为无状态认证自定义
`SecurityContextRepository`](#storing-stateless-authentication-in-the-session)。
::::

如果你使用的是自定义身份验证机制，你可能想 [手动存储
`Authentication`](#store-authentication-manually)。

## 手动存储 `Authentication` {#store-authentication-manually}

在某些情况下，例如，你可能会手动对用户进行身份验证，而不是依赖 Spring
Security 过滤器。 你可以使用自定义过滤器或
{spring-framework-reference-url}/web.html#mvc-controller\[Spring MVC
控制器端点\] 来完成此操作。 如果你想在请求之间保存身份验证，比如在
`HttpSession` 中，你必须这样做：

::: informalexample

Java

:   ``` java
    private SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository(); 

    @PostMapping("/login")
    public void login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) { 
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(
            loginRequest.getUsername(), loginRequest.getPassword()); 
        Authentication authentication = authenticationManager.authenticate(token); 
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication); 
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response); 
    }

    class LoginRequest {

        private String username;
        private String password;

        // getters and setters
    }
    ```
:::

- 将 `SecurityContextRepository` 添加到控制器

- 注入 `HttpServletRequest` 和 `HttpServletResponse` 以便能够保存
  `SecurityContext`

- 使用提供的凭据创建一个未经身份验证的
  `UsernamePasswordAuthenticationToken`

- 调用 `AuthenticationManager#authenticate` 来对用户进行身份验证

- 创建一个 `SecurityContext` 并在其内设置 `Authentication`

- 在 `SecurityContextRepository` 中保存 `SecurityContext`

就这样。 如果你不确定上面示例中的 `securityContextHolderStrategy`
是什么，可以阅读 [使用 `SecurityContextStrategy`
部分](#use-securitycontextholderstrategy) 获取更多信息。

## 正确清除认证 {#properly-clearing-authentication}

如果你使用 Spring Security 的
[注销支持](servlet/authentication/logout.xml)，那么它会为你处理很多事情，包括清除和保存上下文。
但是，假设你需要手动将用户从应用程序中注销。在这种情况下，你需要确保
[正确地清除和保存上下文](servlet/authentication/logout.xml#creating-custom-logout-endpoint)。

## 为无状态认证配置持久化 {#stateless-authentication}

有时没有必要创建和维护一个 `HttpSession`，例如为了跨请求持久化认证。
一些认证机制，如 [HTTP
Basic](servlet/authentication/passwords/basic.xml)，是无状态的，因此会在每次请求时重新认证用户。

如果你不希望创建会话，可以使用
`SessionCreationPolicy.STATELESS`，如下所示：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            // ...
            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            // ...
            sessionManagement {
                sessionCreationPolicy = SessionCreationPolicy.STATELESS
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http create-session="stateless">
        <!-- ... -->
    </http>
    ```
:::

上述配置是 [配置
`SecurityContextRepository`](#customizing-where-authentication-is-stored)
使用 `NullSecurityContextRepository`，同时也
[防止请求被保存在会话中](servlet/architecture.xml#requestcache-prevent-saved-request)。

如果你使用
`SessionCreationPolicy.NEVER`，你可能会注意到应用程序仍然在创建
`HttpSession`。 在大多数情况下，这是因为
[请求被保存在会话中](servlet/architecture.xml#savedrequests)，以便在认证成功后重新请求受保护资源。
为了避免这种情况，请参考
[如何防止请求被保存](servlet/architecture.xml#requestcache-prevent-saved-request)部分。

### 将无状态认证存储在会话中 {#storing-stateless-authentication-in-the-session}

出于某种原因，如果你正在使用一种无状态认证机制，但仍希望将认证信息存储在会话中，可以使用
`HttpSessionSecurityContextRepository` 而不是
`NullSecurityContextRepository`。

对于 [HTTP
Basic](servlet/authentication/passwords/basic.xml)，你可以添加 [一个
`ObjectPostProcessor`](servlet/configuration/java.xml#post-processing-configured-objects)，更改
`BasicAuthenticationFilter` 使用的 `SecurityContextRepository`：

:::: example
::: title
将 HTTP Basic 认证存储在 `HttpSession` 中
:::

Java

:   ``` java
    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http
            // ...
            .httpBasic((basic) -> basic
                .addObjectPostProcessor(new ObjectPostProcessor<BasicAuthenticationFilter>() {
                    @Override
                    public <O extends BasicAuthenticationFilter> O postProcess(O filter) {
                        filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
                        return filter;
                    }
                })
            );

        return http.build();
    }
    ```
::::

上述方法同样适用于其他认证机制，例如 [Bearer Token
认证](servlet/oauth2/resource-server/index.xml)。

# 理解 requireExplicitSave {#requireexplicitsave}

在 Spring Security 5 中，默认行为是使用
[`SecurityContextPersistenceFilter`](#securitycontextpersistencefilter)
将
[`SecurityContext`](servlet/authentication/architecture.xml#servlet-authentication-securitycontext)
自动保存到
[`SecurityContextRepository`](servlet/authentication/persistence.xml#securitycontextrepository)。
保存必须在 `HttpServletResponse` 提交之前以及
`SecurityContextPersistenceFilter` 之前完成。
不幸的是，`SecurityContext`
的自动持久化可能会让用户感到意外，尤其是在请求完成之前（即提交
`HttpServletResponse` 之前）就进行了保存。
此外，跟踪状态以确定是否需要保存也变得复杂，有时会导致不必要的写入
`SecurityContextRepository`（即 `HttpSession`）。

由于这些原因，`SecurityContextPersistenceFilter` 已被弃用，取而代之的是
`SecurityContextHolderFilter`。 在 Spring Security 6 中，默认行为是
[`SecurityContextHolderFilter`](servlet/authentication/persistence.xml#securitycontextholderfilter)
只从 `SecurityContextRepository` 读取 `SecurityContext` 并将其填充到
`SecurityContextHolder` 中。 现在，如果用户希望 `SecurityContext`
在请求之间保持持久性，必须显式地使用 `SecurityContextRepository` 保存
`SecurityContext`。 这消除了歧义，并通过仅在必要时才写入
`SecurityContextRepository`（即 `HttpSession`）来提高性能。

## 它的工作原理 {#how-it-works-requireexplicitsave}

总之，当 `requireExplicitSave` 为 `true` 时，Spring Security 设置
[`SecurityContextHolderFilter`](servlet/authentication/persistence.xml#securitycontextholderfilter)
而不是
[`SecurityContextPersistenceFilter`](servlet/authentication/persistence.xml#securitycontextpersistencefilter)。

# 配置并发会话控制 {#ns-concurrent-sessions}

如果你希望对单个用户的登录能力施加限制，Spring Security
支持通过以下简单添加开箱即用地实现此功能。
首先，你需要在配置中添加以下监听器，以使 Spring Security
了解会话生命周期事件：

::: informalexample

Java

:   ``` java
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun httpSessionEventPublisher(): HttpSessionEventPublisher {
        return HttpSessionEventPublisher()
    }
    ```

web.xml

:   ``` xml
    <listener>
    <listener-class>
        org.springframework.security.web.session.HttpSessionEventPublisher
    </listener-class>
    </listener>
    ```
:::

然后在你的安全配置中添加以下行：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .sessionManagement(session -> session
                .maximumSessions(1)
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = 1
                }
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http>
    ...
    <session-management>
        <concurrency-control max-sessions="1" />
    </session-management>
    </http>
    ```
:::

这将阻止用户多次登录------第二次登录会使第一次登录失效。

使用 Spring Boot，你可以通过以下方式测试上述配置场景：

::: informalexample

Java

:   ``` java
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    @AutoConfigureMockMvc
    public class MaximumSessionsTests {

        @Autowired
        private MockMvc mvc;

        @Test
        void loginOnSecondLoginThenFirstSessionTerminated() throws Exception {
            MvcResult mvcResult = this.mvc.perform(formLogin())
                    .andExpect(authenticated())
                    .andReturn();

            MockHttpSession firstLoginSession = (MockHttpSession) mvcResult.getRequest().getSession();

            this.mvc.perform(get("/").session(firstLoginSession))
                    .andExpect(authenticated());

            this.mvc.perform(formLogin()).andExpect(authenticated());

            // 第一次会话因第二次登录而终止
            this.mvc.perform(get("/").session(firstLoginSession))
                    .andExpect(unauthenticated());
        }

    }
    ```
:::

你可以尝试使用
{gh-samples-url}/servlet/spring-boot/java/session-management/maximum-sessions\[最大会话数示例\]。

另一种常见的情况是你更倾向于阻止第二次登录，这时你可以使用：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .sessionManagement(session -> session
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = 1
                    maxSessionsPreventsLogin = true
                }
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http>
    <session-management>
        <concurrency-control max-sessions="1" error-if-maximum-exceeded="true" />
    </session-management>
    </http>
    ```
:::

第二次登录将被拒绝。
所谓"拒绝"，是指如果使用基于表单的登录，用户将被发送到
`authentication-failure-url`。
如果第二次认证是通过另一个非交互式机制（如"记住我"）发生的，则会向客户端发送"未授权"（401）错误。
如果你希望使用错误页面，可以在 `session-management` 元素中添加属性
`session-authentication-error-url`。

使用 Spring Boot，你可以通过以下方式测试上述配置：

::: informalexample

Java

:   ``` java
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    @AutoConfigureMockMvc
    public class MaximumSessionsPreventLoginTests {

        @Autowired
        private MockMvc mvc;

        @Test
        void loginOnSecondLoginThenPreventLogin() throws Exception {
            MvcResult mvcResult = this.mvc.perform(formLogin())
                    .andExpect(authenticated())
                    .andReturn();

            MockHttpSession firstLoginSession = (MockHttpSession) mvcResult.getRequest().getSession();

            this.mvc.perform(get("/").session(firstLoginSession))
                    .andExpect(authenticated());

            // 第二次登录被阻止
            this.mvc.perform(formLogin()).andExpect(unauthenticated());

            // 第一次会话仍然有效
            this.mvc.perform(get("/").session(firstLoginSession))
                    .andExpect(authenticated());
        }

    }
    ```
:::

如果你为基于表单的登录使用了自定义的身份验证过滤器，则必须显式配置并发会话控制支持。
你可以尝试使用
{gh-samples-url}/servlet/spring-boot/java/session-management/maximum-sessions-prevent-login\[最大会话数阻止登录示例\]。

:::: note
::: title
:::

如果你使用了自定义的 `UserDetails` 实现，请确保重写了 **equals()** 和
**hashCode()** 方法。 Spring Security 中默认的 `SessionRegistry`
实现依赖于内存中的 Map，该 Map 使用这些方法来正确识别和管理用户会话。
如果不重写它们，可能会导致会话跟踪和用户比较行为出现意外问题。
::::

# 检测超时 {#_检测超时}

会话会自行过期，无需采取任何措施来确保安全上下文被移除。
尽管如此，Spring Security
可以检测到会话何时过期，并采取你指定的特定操作。
例如，当用户使用已过期的会话发出请求时，你可能希望重定向到特定端点。
这可以通过 `HttpSecurity` 中的 `invalidSessionUrl` 实现：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .sessionManagement(session -> session
                .invalidSessionUrl("/invalidSession")
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            sessionManagement {
                invalidSessionUrl = "/invalidSession"
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http>
    ...
    <session-management invalid-session-url="/invalidSession" />
    </http>
    ```
:::

请注意，如果你使用此机制检测会话超时，当用户注销后再重新登录而不关闭浏览器时，可能会错误报告错误。
这是因为当你使会话无效时，会话 cookie
不会被清除，即使用户已注销，仍会被重新提交。 如果是这种情况，你可能想
[配置注销以清除会话 cookie](#clearing-session-cookie-on-logout)。

## 自定义无效会话策略 {#_自定义无效会话策略}

`invalidSessionUrl` 是使用
{security-api-url}/org/springframework/security/web/session/SimpleRedirectInvalidSessionStrategy.html\[`SimpleRedirectInvalidSessionStrategy`
实现\] 设置 `InvalidSessionStrategy` 的便捷方法。
如果你想自定义行为，可以实现
{security-api-url}/org/springframework/security/web/session/InvalidSessionStrategy.html\[`InvalidSessionStrategy`\]
接口，并使用 `invalidSessionStrategy` 方法进行配置：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .sessionManagement(session -> session
                .invalidSessionStrategy(new MyCustomInvalidSessionStrategy())
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            sessionManagement {
                invalidSessionStrategy = MyCustomInvalidSessionStrategy()
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http>
    ...
    <session-management invalid-session-strategy-ref="myCustomInvalidSessionStrategy" />
    <bean name="myCustomInvalidSessionStrategy" class="com.example.MyCustomInvalidSessionStrategy" />
    </http>
    ```
:::

# 注销时清除会话 Cookie {#clearing-session-cookie-on-logout}

你可以明确删除 JSESSIONID cookie，例如在注销处理器中使用
[`Clear-Site-Data`
头部](https://w3c.github.io/webappsec-clear-site-data/)：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .logout((logout) -> logout
                .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(COOKIES)))
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            logout {
                addLogoutHandler(HeaderWriterLogoutHandler(ClearSiteDataHeaderWriter(COOKIES)))
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http>
    <logout success-handler-ref="clearSiteDataHandler" />
    <b:bean id="clearSiteDataHandler" class="org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler">
        <b:constructor-arg>
            <b:bean class="org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter">
                <b:constructor-arg>
                    <b:list>
                        <b:value>COOKIES</b:value>
                    </b:list>
                </b:constructor-arg>
            </b:bean>
        </b:constructor-arg>
    </b:bean>
    </http>
    ```
:::

这种方法的优点是与容器无关，只要容器支持 `Clear-Site-Data`
头部即可工作。

作为替代方案，你也可以在注销处理器中使用以下语法：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .logout(logout -> logout
                .deleteCookies("JSESSIONID")
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            logout {
                deleteCookies("JSESSIONID")
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http>
      <logout delete-cookies="JSESSIONID" />
    </http>
    ```
:::

不幸的是，这并不能保证在每个 Servlet
容器中都能正常工作，因此你需要在你的环境中进行测试。

:::: note
::: title
:::

如果你的应用程序运行在代理后面，你也可能通过配置代理服务器来移除会话
cookie。 例如，使用 Apache HTTPD 的
`mod_headers`，以下指令通过在响应注销请求时使其过期来删除 `JSESSIONID`
cookie（假设应用程序部署在 `/tutorial` 路径下）：
::::

``` xml
<LocationMatch "/tutorial/logout">
Header always set Set-Cookie "JSESSIONID=;Path=/tutorial;Expires=Thu, 01 Jan 1970 00:00:00 GMT"
</LocationMatch>
```

更多关于
[清除站点数据](servlet/exploits/headers.xml#servlet-headers-clear-site-data)
和 [注销部分](servlet/authentication/logout.xml) 的详细信息。

# 理解会话固定攻击防护 {#ns-session-fixation}

[会话固定](https://en.wikipedia.org/wiki/Session_fixation)
攻击是一种潜在风险，恶意攻击者可以通过访问网站创建一个会话，然后说服另一用户使用相同的会话登录（例如，通过向他们发送包含会话标识符作为参数的链接）。
Spring Security 通过在用户登录时创建新会话或更改会话 ID
来自动防止此类攻击。

## 配置会话固定保护 {#_配置会话固定保护}

你可以通过选择三种推荐选项之一来控制会话固定保护策略：

- `changeSessionId` - 不创建新会话。 而是使用 Servlet
  容器提供的会话固定保护（`HttpServletRequest#changeSessionId()`）。
  此选项仅在 Servlet 3.1（Java EE 7）及更高版本的容器中可用。
  在较旧的容器中指定它将导致异常。 这是 Servlet 3.1
  及更高版本容器中的默认设置。

- `newSession` - 创建一个新的"干净"会话，不复制现有会话数据（与 Spring
  Security 相关的属性仍将被复制）。

- `migrateSession` - 创建一个新会话并将所有现有会话属性复制到新会话。
  这是 Servlet 3.0 或更早版本容器中的默认设置。

你可以通过以下方式进行会话固定保护配置：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .sessionManagement((session) -> session
                .sessionFixation((sessionFixation) -> sessionFixation
                    .newSession()
                )
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            sessionManagement {
                sessionFixation {
                    newSession()
                }
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http>
      <session-management session-fixation-protection="newSession" />
    </http>
    ```
:::

当发生会话固定保护时，会在应用程序上下文中发布一个
`SessionFixationProtectionEvent`。 如果你使用
`changeSessionId`，这种保护还会通知任何
`jakarta.servlet.http.HttpSessionIdListener`s，因此如果你的代码监听这两个事件，请谨慎使用。

你还可以将会话固定保护设置为 `none`
以禁用它，但这并不推荐，因为它会使你的应用程序易受攻击。

# 使用 `SecurityContextHolderStrategy` {#use-securitycontextholderstrategy}

考虑以下代码块：

::: informalexample

Java

:   ``` java
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
            loginRequest.getUsername(), loginRequest.getPassword());
    Authentication authentication = this.authenticationManager.authenticate(token);
    // ...
    SecurityContext context = SecurityContextHolder.createEmptyContext(); 
    context.setAuthentication(authentication); 
    SecurityContextHolder.setContext(context); 
    ```
:::

1.  通过静态访问 `SecurityContextHolder` 创建一个空的 `SecurityContext`
    实例。

2.  在 `SecurityContext` 实例中设置 `Authentication` 对象。

3.  静态地将 `SecurityContext` 实例设置到 `SecurityContextHolder` 中。

虽然上述代码可以正常工作，但它可能会产生一些不良影响：当组件通过
`SecurityContextHolder` 静态访问 `SecurityContext`
时，如果存在多个想要指定 `SecurityContextHolderStrategy`
的应用程序上下文，这可能会创建竞争条件。 这是因为在
`SecurityContextHolder`
中，每个类加载器只有一个策略，而不是每个应用程序上下文一个策略。

为解决这个问题，组件可以从应用程序上下文中注入
`SecurityContextHolderStrategy`。 默认情况下，它们仍将从
`SecurityContextHolder` 查找策略。

这些变化大多是内部的，但它们为应用程序提供了机会，可以用自动装配
`SecurityContextHolderStrategy` 替代静态访问 `SecurityContext`。
为此，你应该将代码更改为如下所示：

::: informalexample

Java

:   ``` java
    public class SomeClass {

        private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

        public void someMethod() {
            UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(
                    loginRequest.getUsername(), loginRequest.getPassword());
            Authentication authentication = this.authenticationManager.authenticate(token);
            // ...
            SecurityContext context = this.securityContextHolderStrategy.createEmptyContext(); 
            context.setAuthentication(authentication); 
            this.securityContextHolderStrategy.setContext(context); 
        }

    }
    ```
:::

1.  使用配置的 `SecurityContextHolderStrategy` 创建一个空的
    `SecurityContext` 实例。

2.  在 `SecurityContext` 实例中设置 `Authentication` 对象。

3.  将 `SecurityContext` 实例设置到 `SecurityContextHolderStrategy` 中。

# 强制急切创建会话 {#session-mgmt-force-session-creation}

有时，急切地创建会话可能是有价值的。 这可以通过使用
{security-api-url}org/springframework/security/web/session/ForceEagerSessionCreationFilter.html\[`ForceEagerSessionCreationFilter`\]
来实现，可以通过以下方式配置：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            sessionManagement {
                sessionCreationPolicy = SessionCreationPolicy.ALWAYS
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http create-session="ALWAYS">

    </http>
    ```
:::

# 接下来阅读什么 {#_接下来阅读什么}

- 使用 [Spring
  Session](https://docs.spring.io/spring-session/reference/index.html)
  实现集群会话

[^1]: 通过执行重定向进行身份验证的机制（例如表单登录）不会被
    `SessionManagementFilter`
    检测到，因为过滤器在身份验证请求期间不会被调用。
    在这种情况下，会话管理功能必须单独处理。
