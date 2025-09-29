Spring 框架为 CORS 提供了
[一流支持](https://docs.spring.io/spring/docs/current/spring-framework-reference/web.html#mvc-cors)。
CORS 必须在 Spring Security 之前进行处理，因为预检请求（pre-flight
request）不包含任何 Cookie（例如 `JSESSIONID`）。 如果请求中没有
Cookie，并且 Spring Security 先于 CORS
处理，则请求会被判定为未认证（因为请求中没有 Cookie），从而被拒绝。

确保 CORS 优先处理的最简单方法是使用 `CorsFilter`。 用户可以通过提供一个
`CorsConfigurationSource` 将 `CorsFilter` 与 Spring Security 集成。
请注意：**只有当存在 `UrlBasedCorsConfigurationSource` 实例时，Spring
Security 才会自动配置 CORS**。 例如，以下代码将在 Spring Security 中集成
CORS 支持：

::: informalexample

Java

:   ``` java
    @Bean
    UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun corsConfigurationSource(): UrlBasedCorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = listOf("https://example.com")
        configuration.allowedMethods = listOf("GET", "POST")
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }
    ```
:::

以下 XML 配置实现了相同的功能：

``` xml
<http>
    <cors configuration-source-ref="corsSource"/>
    ...
</http>
<b:bean id="corsSource" class="org.springframework.web.cors.UrlBasedCorsConfigurationSource">
    ...
</b:bean>
```

如果你使用的是 Spring MVC 的 CORS 支持，可以省略显式定义
`CorsConfigurationSource`，此时 Spring Security 会自动使用 Spring MVC
中配置的 CORS 规则：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class WebSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                // 如果 Spring MVC 在类路径中，且未提供 CorsConfigurationSource，
                // Spring Security 将使用 Spring MVC 的 CORS 配置
                .cors(withDefaults())
                ...
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    open class WebSecurityConfig {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                // 如果 Spring MVC 在类路径中且未提供 CorsConfigurationSource，
                // Spring Security 将使用 Spring MVC 的 CORS 配置
                cors { }
                // ...
            }
            return http.build()
        }
    }
    ```
:::

以下 XML 配置也实现相同效果：

``` xml
<http>
    <!-- 默认使用 Spring MVC 的 CORS 配置 -->
    <cors />
    ...
</http>
```

如果你的应用中有多个 `CorsConfigurationSource` Bean，Spring Security
**不会自动为你配置 CORS**，因为它无法决定应使用哪一个。 如果你想为每个
`SecurityFilterChain` 指定不同的
`CorsConfigurationSource`，可以直接将其传入 `.cors()` 的 DSL 中。

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class WebSecurityConfig {

        @Bean
        @Order(0)
        public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
            http
                .securityMatcher("/api/**")
                .cors((cors) -> cors
                    .configurationSource(apiConfigurationSource())
                )
                ...
            return http.build();
        }

        @Bean
        @Order(1)
        public SecurityFilterChain myOtherFilterChain(HttpSecurity http) throws Exception {
            http
                .cors((cors) -> cors
                    .configurationSource(myWebsiteConfigurationSource())
                )
                ...
            return http.build();
        }

        UrlBasedCorsConfigurationSource apiConfigurationSource() {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(Arrays.asList("https://api.example.com"));
            configuration.setAllowedMethods(Arrays.asList("GET","POST"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }

        UrlBasedCorsConfigurationSource myWebsiteConfigurationSource() {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
            configuration.setAllowedMethods(Arrays.asList("GET","POST"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }

    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun corsConfigurationSource(): UrlBasedCorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = listOf("https://example.com")
        configuration.allowedMethods = listOf("GET", "POST")
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }
    ```
:::
