:::: example
::: title
`RequestCache` 仅在存在 `continue` 参数时检查已保存的请求
:::

Java

:   ``` java
    @Bean
    DefaultSecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setMatchingRequestParameterName("continue");
        http
            // ...
            .requestCache((cache) -> cache
                .requestCache(requestCache)
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: HttpSecurity): SecurityFilterChain {
        val httpRequestCache = HttpSessionRequestCache()
        httpRequestCache.setMatchingRequestParameterName("continue")
        http {
            requestCache {
                requestCache = httpRequestCache
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http auto-config="true">
        <!-- ... -->
        <request-cache ref="requestCache"/>
    </http>

    <b:bean id="requestCache" class="org.springframework.security.web.savedrequest.HttpSessionRequestCache"
        p:matchingRequestParameterName="continue"/>
    ```
::::
