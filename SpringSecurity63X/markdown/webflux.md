Spring Security 的 WebFlux 支持依赖于 `WebFilter`，适用于 Spring WebFlux
和 Spring WebFlux.Fn。以下是一些演示代码的示例应用：

- Hello WebFlux
  {gh-samples-url}/reactive/webflux/java/hello-security\[hellowebflux\]

- Hello WebFlux.Fn
  {gh-samples-url}/reactive/webflux-fn/hello-security\[hellowebfluxfn\]

- Hello WebFlux Method
  {gh-samples-url}/reactive/webflux/java/method\[hellowebflux-method\]

# 最小化的 WebFlux 安全配置 {#_最小化的_webflux_安全配置}

以下列出的是一个最小化的 WebFlux 安全配置：

:::: example
::: title
最小化的 WebFlux 安全配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebFluxSecurity
    public class HelloWebfluxSecurityConfig {

        @Bean
        public MapReactiveUserDetailsService userDetailsService() {
            UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER")
                .build();
            return new MapReactiveUserDetailsService(user);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebFluxSecurity
    class HelloWebfluxSecurityConfig {

        @Bean
        fun userDetailsService(): ReactiveUserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                    .username("user")
                    .password("user")
                    .roles("USER")
                    .build()
            return MapReactiveUserDetailsService(userDetails)
        }
    }
    ```
::::

该配置提供了表单登录和 HTTP Basic
认证，设置了访问任何页面都需要用户认证的授权规则，生成了默认的登录页和登出页，配置了安全相关的
HTTP 头信息，并启用了 CSRF 保护等功能。

# 显式的 WebFlux 安全配置 {#_显式的_webflux_安全配置}

以下是一个显式版本的最小化 WebFlux 安全配置：

:::: example
::: title
显式的 WebFlux 安全配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebFluxSecurity
    public class HelloWebfluxSecurityConfig {

        @Bean
        public MapReactiveUserDetailsService userDetailsService() {
            UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER")
                .build();
            return new MapReactiveUserDetailsService(user);
        }

        @Bean
        public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
            http
                .authorizeExchange(exchanges -> exchanges
                    .anyExchange().authenticated()
                )
                .httpBasic(withDefaults())
                .formLogin(withDefaults());
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.config.web.server.invoke

    @Configuration
    @EnableWebFluxSecurity
    class HelloWebfluxSecurityConfig {

        @Bean
        fun userDetailsService(): ReactiveUserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                    .username("user")
                    .password("user")
                    .roles("USER")
                    .build()
            return MapReactiveUserDetailsService(userDetails)
        }

        @Bean
        fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                formLogin { }
                httpBasic { }
            }
        }
    }
    ```
::::

:::: note
::: title
:::

请确保导入 `org.springframework.security.config.web.server.invoke`
函数，以在类中启用 Kotlin DSL。IDE
不总是自动导入该方法，可能导致编译错误。
::::

此配置显式地设置了与最小配置相同的所有功能。在此基础上，你可以更轻松地修改默认行为。

你可以在单元测试中找到更多显式配置的示例，只需在 `config/src/test/`
目录下搜索
[`EnableWebFluxSecurity`](https://github.com/spring-projects/spring-security/search?q=path%3Aconfig%2Fsrc%2Ftest%2F+EnableWebFluxSecurity)
即可。

## 多链支持（Multiple Chains Support） {#jc-webflux-multiple-filter-chains}

你可以配置多个 `SecurityWebFilterChain` 实例，通过 `RequestMatcher`
来区分不同的请求路径并进行独立的安全配置。

例如，可以为以 `/api` 开头的 URL 单独设置安全配置：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebFluxSecurity
    static class MultiSecurityHttpConfig {

        @Order(Ordered.HIGHEST_PRECEDENCE)                                                      
        @Bean
        SecurityWebFilterChain apiHttpSecurity(ServerHttpSecurity http) {
            http
                .securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**"))      
                .authorizeExchange((exchanges) -> exchanges
                    .anyExchange().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerSpec::jwt);                           
            return http.build();
        }

        @Bean
        SecurityWebFilterChain webHttpSecurity(ServerHttpSecurity http) {                       
            http
                .authorizeExchange((exchanges) -> exchanges
                    .anyExchange().authenticated()
                )
                .httpBasic(withDefaults());                                                     
            return http.build();
        }

        @Bean
        ReactiveUserDetailsService userDetailsService() {
            return new MapReactiveUserDetailsService(
                    PasswordEncodedUser.user(), PasswordEncodedUser.admin());
        }

    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.config.web.server.invoke

    @Configuration
    @EnableWebFluxSecurity
    open class MultiSecurityHttpConfig {
        @Order(Ordered.HIGHEST_PRECEDENCE)                                                      
        @Bean
        open fun apiHttpSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                securityMatcher(PathPatternParserServerWebExchangeMatcher("/api/**"))           
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt { }                                                                     
                }
            }
        }

        @Bean
        open fun webHttpSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {            
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                httpBasic { }                                                                   
            }
        }

        @Bean
        open fun userDetailsService(): ReactiveUserDetailsService {
            return MapReactiveUserDetailsService(
                PasswordEncodedUser.user(), PasswordEncodedUser.admin()
            )
        }
    }
    ```
:::

- 使用 `@Order` 注解配置 `SecurityWebFilterChain`，指定 Spring Security
  应优先考虑哪一个过滤器链

- 使用 `PathPatternParserServerWebExchangeMatcher` 指定此
  `SecurityWebFilterChain` 仅应用于以 `/api/` 开头的 URL 路径

- 指定用于 `/api/**` 端点的认证机制（此处使用 JWT 格式的 OAuth2
  资源服务器）

- 创建另一个优先级较低的 `SecurityWebFilterChain` 实例，用于匹配其余所有
  URL

- 指定应用程序其他部分使用的认证机制（此处为 HTTP Basic）

Spring Security 会为每个请求选择一个 `SecurityWebFilterChain`
`@Bean`。它按照 `securityMatcher` 的定义顺序进行匹配。

在本例中，如果请求的 URL 路径以 `/api` 开头，则使用
`apiHttpSecurity`；否则使用 `webHttpSecurity` ------
后者隐含了一个匹配所有请求的 `securityMatcher`。
