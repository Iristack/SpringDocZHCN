:::: example
::: title
Explicit Saving of SecurityContext
:::

Java

:   ``` java
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            // ...
            .securityContext((securityContext) -> securityContext
                .requireExplicitSave(true)
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: HttpSecurity): SecurityFilterChain {
        http {
            securityContext {
                requireExplicitSave = true
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http security-context-explicit-save="true">
        <!-- ... -->
    </http>
    ```
::::

启用此配置后，任何通过 `SecurityContextHolder` 设置 `SecurityContext`
的代码，如果希望在请求之间持久化该上下文，则必须同时将 `SecurityContext`
保存到 `SecurityContextRepository` 中。

例如，以下代码：

:::: example
::: title
使用 `SecurityContextPersistenceFilter` 设置 `SecurityContextHolder`
:::

Java

:   ``` java
    SecurityContextHolder.setContext(securityContext);
    ```

Kotlin

:   ``` kotlin
    SecurityContextHolder.setContext(securityContext)
    ```
::::

应替换为：

:::: example
::: title
使用 `SecurityContextHolderFilter` 设置 `SecurityContextHolder`
:::

Java

:   ``` java
    SecurityContextHolder.setContext(securityContext);
    securityContextRepository.saveContext(securityContext, httpServletRequest, httpServletResponse);
    ```

Kotlin

:   ``` kotlin
    SecurityContextHolder.setContext(securityContext)
    securityContextRepository.saveContext(securityContext, httpServletRequest, httpServletResponse)
    ```
::::
