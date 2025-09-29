{security-api-url}org/springframework/security/core/userdetails/UserDetailsService.html\[`UserDetailsService`\]
被
[`DaoAuthenticationProvider`](servlet/authentication/passwords/dao-authentication-provider.xml#servlet-authentication-daoauthenticationprovider)
使用，用于检索用户名、密码以及其他与基于用户名和密码的身份验证相关的属性。
Spring Security 提供了 `UserDetailsService` 的多种实现方式，包括
[内存中存储](servlet/authentication/passwords/in-memory.xml#servlet-authentication-inmemory)、[JDBC
存储](servlet/authentication/passwords/jdbc.xml#servlet-authentication-jdbc)
以及
[缓存](servlet/authentication/passwords/caching.xml#servlet-authentication-caching-user-details)
实现。

您可以通过将自定义的 `UserDetailsService` 声明为一个 Bean
来实现自定义身份验证。 例如，以下代码示例展示了如何进行自定义认证，假设
`CustomUserDetailsService` 实现了 `UserDetailsService` 接口：

:::: note
::: title
:::

此方法仅在 `AuthenticationManagerBuilder` 尚未配置且未定义
`AuthenticationProviderBean` 时生效。
::::

自定义 UserDetailsService Bean

::: informalexample

Java

:   ``` java
    @Bean
    CustomUserDetailsService customUserDetailsService() {
        return new CustomUserDetailsService();
    }
    ```

XML

:   ``` java
    <b:bean class="example.CustomUserDetailsService"/>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun customUserDetailsService() = CustomUserDetailsService()
    ```
:::
