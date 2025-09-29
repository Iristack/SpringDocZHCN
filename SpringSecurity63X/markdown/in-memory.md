Spring Security 的 `InMemoryUserDetailsManager` 实现了
[UserDetailsService](servlet/authentication/passwords/user-details-service.xml#servlet-authentication-userdetailsservice)，用于支持基于用户名/密码的身份验证，并将用户信息存储在内存中。
`InMemoryUserDetailsManager` 通过实现 `UserDetailsManager` 接口来管理
`UserDetails` 对象。 当 Spring Security 被配置为
[接受用户名和密码](#servlet-authentication-unpwd-input)
进行身份验证时，就会使用基于 `UserDetails` 的认证机制。

在以下示例中，我们使用 [Spring Boot
CLI](features/authentication/password-storage.xml#authentication-password-storage-boot-cli)
将明文密码 `password` 编码，得到的加密结果为
`{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW`：

:::: example
::: title
InMemoryUserDetailsManager Java 配置
:::

Java

:   ``` java
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder()
            .username("user")
            .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
            .roles("USER")
            .build();
        UserDetails admin = User.builder()
            .username("admin")
            .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
            .roles("USER", "ADMIN")
            .build();
        return new InMemoryUserDetailsManager(user, admin);
    }
    ```

XML

:   ``` xml
    <user-service>
        <user name="user"
            password="{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW"
            authorities="ROLE_USER" />
        <user name="admin"
            password="{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW"
            authorities="ROLE_USER,ROLE_ADMIN" />
    </user-service>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun users(): UserDetailsService {
        val user = User.builder()
            .username("user")
            .password("{bcrypt}$2a$10\$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
            .roles("USER")
            .build()
        val admin = User.builder()
            .username("admin")
            .password("{bcrypt}$2a$10\$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
            .roles("USER", "ADMIN")
            .build()
        return InMemoryUserDetailsManager(user, admin)
    }
    ```
::::

上述示例以安全格式存储密码，但在初学者体验方面仍有不足。

在以下示例中，我们使用
[User.withDefaultPasswordEncoder](features/authentication/password-storage.xml#authentication-password-storage-dep-getting-started)
方法，确保内存中存储的密码是经过编码保护的。
但需要注意的是，这种方式无法防止通过反编译源代码获取密码。
因此，`User.withDefaultPasswordEncoder`
**仅适用于快速入门场景**，**不推荐用于生产环境**。

:::: example
::: title
InMemoryUserDetailsManager 使用 User.withDefaultPasswordEncoder
:::

Java

:   ``` java
    @Bean
    public UserDetailsService users() {
        // 构建器会在保存到内存前自动对密码进行编码
        UserBuilder users = User.withDefaultPasswordEncoder();
        UserDetails user = users
            .username("user")
            .password("password")
            .roles("USER")
            .build();
        UserDetails admin = users
            .username("admin")
            .password("password")
            .roles("USER", "ADMIN")
            .build();
        return new InMemoryUserDetailsManager(user, admin);
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun users(): UserDetailsService {
        // 构建器会在保存到内存前自动对密码进行编码
        val users = User.withDefaultPasswordEncoder()
        val user = users
            .username("user")
            .password("password")
            .roles("USER")
            .build()
        val admin = users
            .username("admin")
            .password("password")
            .roles("USER", "ADMIN")
            .build()
        return InMemoryUserDetailsManager(user, admin)
    }
    ```
::::

目前没有简单的方法可以在基于 XML 的配置中使用
`User.withDefaultPasswordEncoder`。
对于演示或快速入门目的，可以选择在密码前加上 `{noop}` 前缀，表示
[不对密码进行编码处理](features/authentication/password-storage.xml#authentication-password-storage-dpe-format)：

:::: formalpara
::: title
\<user-service\> 使用 `{noop}` 的 XML 配置
:::

``` xml
<user-service>
    <user name="user"
        password="{noop}password"
        authorities="ROLE_USER" />
    <user name="admin"
        password="{noop}password"
        authorities="ROLE_USER,ROLE_ADMIN" />
</user-service>
```
::::
