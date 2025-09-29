Spring Security 提供了对缓存 `UserDetails` 的支持，可通过
[`CachingUserDetailsService`](#servlet-authentication-caching-user-details-service)
实现。 此外，你也可以使用 Spring 框架提供的
[`@Cacheable`](#servlet-authentication-caching-user-details-cacheable)
注解来实现缓存。 无论采用哪种方式，都需要 [禁用凭证擦除（disable
credential
erasure）](#servlet-authentication-caching-user-details-credential-erasure)，以便能够验证从缓存中获取的密码。

# `CachingUserDetailsService` {#servlet-authentication-caching-user-details-service}

Spring Security 的 `CachingUserDetailsService` 实现了
[UserDetailsService](servlet/authentication/passwords/user-details-service.xml#servlet-authentication-userdetailsservice)，用于支持
`UserDetails` 的缓存功能。 `CachingUserDetailsService`
通过将请求委托给指定的 `UserDetailsService`
来提供缓存支持，并将结果存储在 `UserCache`
中，以减少后续调用中的重复计算。

以下示例定义了一个 `@Bean`，封装了一个具体的 `UserDetailsService`
实现和一个用于缓存 `UserDetails` 的 `UserCache`：

:::: example
::: title
提供一个 `CachingUserDetailsService` `@Bean`
:::

Java

:   ``` java
    @Bean
    public CachingUserDetailsService cachingUserDetailsService(UserCache userCache) {
        UserDetailsService delegate = ...;
        CachingUserDetailsService service = new CachingUserDetailsService(delegate);
        service.setUserCache(userCache);
        return service;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun cachingUserDetailsService(userCache: UserCache): CachingUserDetailsService {
        val delegate: UserDetailsService = ...
        val service = CachingUserDetailsService(delegate)
        service.userCache = userCache
        return service
    }
    ```
::::

# `@Cacheable` {#servlet-authentication-caching-user-details-cacheable}

另一种方法是在你的 `UserDetailsService` 实现中使用 Spring 框架的
{spring-framework-reference-url}integration.html#cache-annotations-cacheable\[`@Cacheable`\]
注解，根据用户名缓存 `UserDetails`。
这种方式的优点是配置更简单，特别是当你已经在应用程序的其他部分使用了缓存时。

以下示例假设缓存功能已经配置好，并为 `loadUserByUsername` 方法添加了
`@Cacheable` 注解：

:::: example
::: title
使用 `@Cacheable` 注解的 `UserDetailsService`
:::

Java

:   ``` java
    @Service
    public class MyCustomUserDetailsImplementation implements UserDetailsService {

        @Override
        @Cacheable
        public UserDetails loadUserByUsername(String username) {
            // 获取用户详细信息的逻辑
            return userDetails;
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Service
    class MyCustomUserDetailsImplementation : UserDetailsService {

        @Cacheable
        override fun loadUserByUsername(username: String): UserDetails {
            // 获取用户详细信息的逻辑
            return userDetails
        }
    }
    ```
::::

# 禁用凭证擦除 {#servlet-authentication-caching-user-details-credential-erasure}

无论你使用的是
[`CachingUserDetailsService`](#servlet-authentication-caching-user-details-service)
还是
[`@Cacheable`](#servlet-authentication-caching-user-details-cacheable)，都需要禁用
[凭证擦除（credential
erasure）](servlet/authentication/architecture.xml#servlet-authentication-providermanager-erasing-credentials)
功能，这样才能确保从缓存中取出的 `UserDetails`
包含密码字段，从而可以进行密码校验。

以下示例通过配置 Spring Security 提供的
`AuthenticationManagerBuilder`，禁用了全局 `AuthenticationManager`
的凭证擦除功能：

:::: example
::: title
为全局 `AuthenticationManager` 禁用凭证擦除
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            // ...
            return http.build();
        }

        @Bean
        public UserDetailsService userDetailsService() {
            // 返回一个缓存用户的 UserDetailsService
            // ...
        }

        @Autowired
        public void configure(AuthenticationManagerBuilder builder) {
            builder.eraseCredentials(false);
        }

    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.config.annotation.web.invoke

    @Configuration
    @EnableWebSecurity
    class SecurityConfig {

        @Bean
        fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            // ...
            return http.build()
        }

        @Bean
        fun userDetailsService(): UserDetailsService {
            // 返回一个缓存用户的 UserDetailsService
            // ...
        }

        @Autowired
        fun configure(builder: AuthenticationManagerBuilder) {
            builder.eraseCredentials(false)
        }

    }
    ```
::::
