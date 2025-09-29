所有基于 HTTP 的通信都应通过使用 TLS 来进行保护，详情请参见 [TLS
配置](features/exploits/http.xml#http)。

本节介绍与 Servlet 相关的特定功能，这些功能有助于 HTTPS 的使用。

# 重定向到 HTTPS {#servlet-http-redirect}

如果客户端使用 HTTP 而非 HTTPS 发起请求，你可以配置 Spring Security
将其重定向至 HTTPS。

例如，以下 Java 或 Kotlin 配置会将所有 HTTP 请求重定向到 HTTPS：

:::: example
::: title
重定向到 HTTPS
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class WebSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                // ...
                .requiresChannel(channel -> channel
                    .anyRequest().requiresSecure()
                );
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                // ...
                requiresChannel {
                    secure(AnyRequestMatcher.INSTANCE, "REQUIRES_SECURE_CHANNEL")
                }
            }
            return http.build()
        }
    }
    ```
::::

以下 XML 配置将所有 HTTP 请求重定向到 HTTPS：

:::: formalpara
::: title
使用 XML 配置重定向到 HTTPS
:::

``` xml
<http>
    <intercept-url pattern="/**" access="ROLE_USER" requires-channel="https"/>
...
</http>
```
::::

# 严格传输安全（Strict Transport Security） {#servlet-hsts}

Spring Security 支持
[严格传输安全（HSTS）](servlet/exploits/headers.xml#servlet-headers-hsts)，并默认启用该功能。

# 代理服务器配置 {#servlet-http-proxy-server}

Spring Security 可以
[与代理服务器集成](features/exploits/http.xml#http-proxy-server)。
