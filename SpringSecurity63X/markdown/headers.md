你可以使用 [安全HTTP响应头](features/exploits/headers.xml#headers)
来提高Web应用程序的安全性。
本节专门介绍基于Servlet的安全HTTP响应头支持。

# 默认安全头 {#servlet-headers-default}

Spring Security 提供了
[默认的安全HTTP响应头集合](features/exploits/headers.xml#headers-default)，以提供安全的默认配置。
尽管这些头部都被认为是最佳实践，但需要注意的是，并非所有客户端都使用这些头部，因此建议进行额外的测试。

你可以自定义特定的头部。例如，假设你希望保留默认值，但希望为
[X-Frame-Options](#servlet-headers-frame-options) 指定 `SAMEORIGIN`。

你可以通过以下配置实现：

:::: example
::: title
自定义默认安全头
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
                .headers(headers -> headers
                    .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <frame-options policy="SAMEORIGIN" />
        </headers>
    </http>
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
                headers {
                    frameOptions {
                        sameOrigin = true
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

如果你不希望添加默认值，并且希望明确控制应使用的头部，则可以禁用默认值。
下一段代码列出了如何操作。

如果你使用 Spring Security 的配置，下面的代码将仅添加
[缓存控制](features/exploits/headers.xml#headers-cache-control) 头部：

:::: example
::: title
自定义缓存控制头
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
                .headers(headers -> headers
                    // 除非显式列出，否则不使用任何默认头
                    .defaultsDisabled()
                    .cacheControl(withDefaults())
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers defaults-disabled="true">
            <cache-control/>
        </headers>
    </http>
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
                headers {
                    // 除非显式列出，否则不使用任何默认头
                    defaultsDisabled = true
                    cacheControl {
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

如有必要，你可以使用以下配置禁用所有HTTP安全响应头：

:::: example
::: title
禁用所有HTTP安全头
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
                .headers(headers -> headers.disable());
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers disabled="true" />
    </http>
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
                headers {
                    disable()
                }
            }
            return http.build()
        }
    }
    ```
::::

# 缓存控制 {#servlet-headers-cache-control}

Spring Security 默认包含
[缓存控制](features/exploits/headers.xml#headers-cache-control) 头部。

然而，如果你确实想要缓存特定的响应，你的应用程序可以选择性地调用
[`HttpServletResponse.setHeader(String,String)`](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletResponse.html#setHeader(java.lang.String,java.lang.String))
来覆盖由 Spring Security 设置的头部。你可以使用此方法确保内容（如
CSS、JavaScript 和图像）被正确缓存。

当你使用 Spring Web MVC 时，这通常在你的配置中完成。你可以在 Spring
参考文档的
[静态资源](https://docs.spring.io/spring/docs/5.0.0.RELEASE/spring-framework-reference/web.html#mvc-config-static-resources)
部分找到如何操作的详细信息。

如有必要，你也可以禁用 Spring Security 的缓存控制 HTTP 响应头。

:::: example
::: title
禁用缓存控制
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
                .headers(headers -> headers
                    .cacheControl(cache -> cache.disable())
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <cache-control disabled="true"/>
        </headers>
    </http>
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
           http {
                headers {
                    cacheControl {
                        disable()
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# 内容类型选项 {#servlet-headers-content-type-options}

Spring Security 默认包含
[内容类型](features/exploits/headers.xml#headers-content-type-options)
头部。但是，你可以禁用它：

:::: example
::: title
禁用内容类型选项
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
                .headers(headers -> headers
                    .contentTypeOptions(contentTypeOptions -> contentTypeOptions.disable())
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <content-type-options disabled="true"/>
        </headers>
    </http>
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
           http {
                headers {
                    contentTypeOptions {
                        disable()
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# HTTP严格传输安全 (HSTS) {#servlet-headers-hsts}

默认情况下，Spring Security 提供
[严格传输安全](features/exploits/headers.xml#headers-hsts)
头部。然而，你可以显式地自定义结果。以下示例显式提供了 HSTS：

:::: example
::: title
严格传输安全性
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
                .headers(headers -> headers
                    .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .preload(true)
                        .maxAgeInSeconds(31536000)
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <hsts
                include-subdomains="true"
                max-age-seconds="31536000"
                preload="true" />
        </headers>
    </http>
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    httpStrictTransportSecurity {
                        includeSubDomains = true
                        preload = true
                        maxAgeInSeconds = 31536000
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# HTTP公钥固定 (HPKP) {#servlet-headers-hpkp}

Spring Security 为
[HTTP公钥固定](features/exploits/headers.xml#headers-hpkp) 提供了
Servlet 支持，但它已被
[不再推荐使用](features/exploits/headers.xml#headers-hpkp-deprecated)。

你可以通过以下配置启用 HPKP 头部：

:::: example
::: title
HTTP 公钥固定
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
                .headers(headers -> headers
                    .httpPublicKeyPinning(hpkp -> hpkp
                        .includeSubDomains(true)
                        .reportUri("https://example.net/pkp-report")
                        .addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=")
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <hpkp
                include-subdomains="true"
                report-uri="https://example.net/pkp-report">
                <pins>
                    <pin algorithm="sha256">d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=</pin>
                    <pin algorithm="sha256">E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=</pin>
                </pins>
            </hpkp>
        </headers>
    </http>
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    httpPublicKeyPinning {
                        includeSubDomains = true
                        reportUri = "https://example.net/pkp-report"
                        pins = mapOf("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" to "sha256",
                                "E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" to "sha256")
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# X-Frame-Options {#servlet-headers-frame-options}

默认情况下，Spring Security 使用
[X-Frame-Options](features/exploits/headers.xml#headers-frame-options)
指示浏览器阻止反射型 XSS 攻击。

例如，以下配置指定 Spring Security 不再指示浏览器阻止内容：

:::: example
::: title
X-Frame-Options: SAMEORIGIN
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
                .headers(headers -> headers
                    .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <frame-options
            policy="SAMEORIGIN" />
        </headers>
    </http>
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    frameOptions {
                        sameOrigin = true
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# X-XSS-Protection {#servlet-headers-xss-protection}

默认情况下，Spring Security 使用 [X-XSS-Protection
header](#headers-xss-protection)
指示浏览器禁用XSS审计器。然而，你可以更改此默认设置。例如，以下配置指定Spring
Security指示兼容的浏览器启用过滤并阻止内容：

:::: example
::: title
X-XSS-Protection 自定义
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
                .headers(headers -> headers
                    .xssProtection(xss -> xss
                        .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <xss-protection headerValue="1; mode=block"/>
        </headers>
    </http>
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            // ...
            http {
                headers {
                    xssProtection {
                        headerValue = XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# 内容安全策略 (CSP) {#servlet-headers-csp}

Spring Security 默认不添加
[内容安全策略](features/exploits/headers.xml#headers-csp)，因为合理的默认值在不了解应用程序上下文的情况下无法确定。
Web
应用程序作者必须声明要对受保护资源强制执行或监控的安全策略（或策略）。

考虑以下安全策略：

:::: formalpara
::: title
内容安全策略示例
:::

``` http
Content-Security-Policy: script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/
```
::::

给定上述安全策略，你可以启用 CSP 头：

:::: example
::: title
内容安全策略
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
                .headers(headers -> headers
                    .contentSecurityPolicy(csp -> csp
                        .policyDirectives("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/")
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <content-security-policy
                policy-directives="script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/" />
        </headers>
    </http>
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
                headers {
                    contentSecurityPolicy {
                        policyDirectives = "script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/"
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

要启用 CSP 的 `report-only` 头，请提供以下配置：

:::: example
::: title
内容安全策略报告模式
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
                .headers(headers -> headers
                    .contentSecurityPolicy(csp -> csp
                        .policyDirectives("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/")
                        .reportOnly()
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <content-security-policy
                policy-directives="script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/"
                report-only="true" />
        </headers>
    </http>
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
                headers {
                    contentSecurityPolicy {
                        policyDirectives = "script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/"
                        reportOnly = true
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# 引用策略 {#servlet-headers-referrer}

Spring Security 默认不添加
[引用策略](features/exploits/headers.xml#headers-referrer) 头部。
你可以通过以下配置启用引用策略头：

:::: example
::: title
引用策略
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
                .headers(headers -> headers
                    .referrerPolicy(referrer -> referrer
                        .policy(ReferrerPolicy.SAME_ORIGIN)
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <referrer-policy policy="same-origin" />
        </headers>
    </http>
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
                headers {
                    referrerPolicy {
                        policy = ReferrerPolicy.SAME_ORIGIN
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# 功能策略 {#servlet-headers-feature}

Spring Security 默认不添加
[功能策略](features/exploits/headers.xml#headers-feature) 头部。
考虑以下 `Feature-Policy` 头：

:::: formalpara
::: title
Feature-Policy 示例
:::

    Feature-Policy: geolocation 'self'
::::

你可以通过以下配置启用上述功能策略头：

:::: example
::: title
Feature-Policy
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
                .headers(headers -> headers
                    .featurePolicy("geolocation 'self'")
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <feature-policy policy-directives="geolocation 'self'" />
        </headers>
    </http>
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
                headers {
                    featurePolicy("geolocation 'self'")
                }
            }
            return http.build()
        }
    }
    ```
::::

# 权限策略 {#servlet-headers-permissions}

Spring Security 默认不添加
[权限策略](features/exploits/headers.xml#headers-permissions) 头部。
考虑以下 `Permissions-Policy` 头：

:::: formalpara
::: title
Permissions-Policy 示例
:::

    Permissions-Policy: geolocation=(self)
::::

你可以通过以下配置启用上述权限策略头：

:::: example
::: title
Permissions-Policy
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
                .headers(headers -> headers
                    .permissionsPolicy(permissions -> permissions
                        .policy("geolocation=(self)")
                    )
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <permissions-policy policy="geolocation=(self)" />
        </headers>
    </http>
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
                headers {
                    permissionPolicy {
                        policy = "geolocation=(self)"
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

# 清除站点数据 {#servlet-headers-clear-site-data}

Spring Security 默认不添加
[清除站点数据](features/exploits/headers.xml#headers-clear-site-data)
头部。 考虑以下清除站点数据头：

:::: formalpara
::: title
清除站点数据示例
:::

    Clear-Site-Data: "cache", "cookies"
::::

你可以在注销时通过以下配置发送上述头：

:::: example
::: title
清除站点数据
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
                .logout((logout) -> logout
                    .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(CACHE, COOKIES)))
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
                logout {
                    addLogoutHandler(HeaderWriterLogoutHandler(ClearSiteDataHeaderWriter(CACHE, COOKIES)))
                }
            }
            return http.build()
        }
    }
    ```
::::

# 自定义头 {#servlet-headers-custom}

Spring Security
提供了机制，使向应用程序添加更常见的安全头变得方便。同时，它也提供了钩子来添加自定义头。

## 静态头 {#servlet-headers-static}

有时，你可能希望注入一些未内置支持的自定义安全头到你的应用程序中。
考虑以下自定义安全头：

    X-Custom-Security-Header: header-value

根据上述头，你可以通过以下配置将其添加到响应中：

:::: example
::: title
StaticHeadersWriter
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
                .headers(headers -> headers
                    .addHeaderWriter(new StaticHeadersWriter("X-Custom-Security-Header","header-value"))
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <header name="X-Custom-Security-Header" value="header-value"/>
        </headers>
    </http>
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
                headers {
                    addHeaderWriter(StaticHeadersWriter("X-Custom-Security-Header","header-value"))
                }
            }
            return http.build()
        }
    }
    ```
::::

## 头写入器 {#servlet-headers-writer}

当命名空间或 Java 配置不支持你想要的头时，你可以创建一个自定义的
`HeadersWriter` 实例，甚至提供 `HeadersWriter` 的自定义实现。

下一个示例使用了 `XFrameOptionsHeaderWriter`
的自定义实例。如果你想显式配置
[X-Frame-Options](#servlet-headers-frame-options)，可以通过以下配置实现：

:::: example
::: title
头写入器
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
                .headers(headers -> headers
                    .addHeaderWriter(new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN))
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <header ref="frameOptionsWriter"/>
        </headers>
    </http>
    <!-- 需要 c 命名空间。
    参见 https://docs.spring.io/spring/docs/current/spring-framework-reference/htmlsingle/#beans-c-namespace
    -->
    <beans:bean id="frameOptionsWriter"
        class="org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter"
        c:frameOptionsMode="SAMEORIGIN"/>
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
                headers {
                    addHeaderWriter(XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN))
                }
            }
            return http.build()
        }
    }
    ```
::::

## DelegatingRequestMatcherHeaderWriter {#headers-delegatingrequestmatcherheaderwriter}

有时，你可能只想对某些请求写入头。例如，也许你只想保护登录页面不被嵌入框架中。
你可以使用 `DelegatingRequestMatcherHeaderWriter` 来实现这一点。

以下配置示例使用了 `DelegatingRequestMatcherHeaderWriter`：

:::: example
::: title
DelegatingRequestMatcherHeaderWriter Java 配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class WebSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            RequestMatcher matcher = new AntPathRequestMatcher("/login");
            DelegatingRequestMatcherHeaderWriter headerWriter =
                new DelegatingRequestMatcherHeaderWriter(matcher,new XFrameOptionsHeaderWriter());
            http
                // ...
                .headers(headers -> headers
                    .frameOptions(frameOptions -> frameOptions.disable())
                    .addHeaderWriter(headerWriter)
                );
            return http.build();
        }
    }
    ```

XML

:   ``` xml
    <http>
        <!-- ... -->

        <headers>
            <frame-options disabled="true"/>
            <header ref="headerWriter"/>
        </headers>
    </http>

    <beans:bean id="headerWriter"
        class="org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter">
        <beans:constructor-arg>
            <bean class="org.springframework.security.web.util.matcher.AntPathRequestMatcher"
                c:pattern="/login"/>
        </beans:constructor-arg>
        <beans:constructor-arg>
            <beans:bean
                class="org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter"/>
        </beans:constructor-arg>
    </beans:bean>
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            val matcher: RequestMatcher = AntPathRequestMatcher("/login")
            val headerWriter = DelegatingRequestMatcherHeaderWriter(matcher, XFrameOptionsHeaderWriter())
           http {
                headers {
                    frameOptions {
                        disable()
                    }
                    addHeaderWriter(headerWriter)
                }
            }
            return http.build()
        }
    }
    ```
::::
