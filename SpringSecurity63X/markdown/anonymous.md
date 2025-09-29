# 概述 {#anonymous-overview}

通常来说，采用"默认拒绝"（`deny-by-default`）的安全策略是一种良好的安全实践，即明确指定允许的内容，其余一切均禁止。对未认证用户可访问的资源进行定义也属于类似情况，特别是对于
Web 应用程序而言。许多网站要求用户必须经过身份验证才能访问大部分
URL，仅允许少数几个页面（例如首页和登录页）例外。在这种情况下，最简便的方式是仅为这些特定的
URL 定义访问控制属性，而不是为每一个受保护的资源都单独配置。

换句话说，有时我们希望默认要求具备 `ROLE_SOMETHING`
权限，并仅对某些特殊情况（如登录、登出和首页）作出例外处理。你也可以完全将这些页面排除在过滤器链之外，从而绕过访问控制检查，但这可能带来其他问题，尤其是当这些页面对已认证用户和未认证用户展示不同行为时。

这正是我们所说的**匿名认证**（Anonymous
Authentication）。需要注意的是，"匿名认证用户"与"未认证用户"在概念上并无实质区别。Spring
Security 的匿名认证机制只是提供了一种更便捷的方式来配置访问控制属性。像
`getCallerPrincipal` 这样的 Servlet API 调用仍然会返回 `null`，即使此时
`SecurityContextHolder` 中实际上存在一个匿名认证对象。

匿名认证在其他场景下也很有用，例如当审计拦截器查询
`SecurityContextHolder` 以确定哪个主体执行了某项操作时。如果开发者能确保
`SecurityContextHolder` 中始终包含一个 `Authentication` 对象而不会是
`null`，那么相关类就可以编写得更加健壮可靠。

# 配置 {#anonymous-config}

当你使用 HTTP 配置（自 Spring Security 3.0
引入）时，系统会自动提供匿名认证支持。你可以通过 `<anonymous>`
元素来自定义（或禁用）该功能。除非你使用传统的 Bean
配置方式，否则无需手动配置此处描述的 Bean。

三个类共同协作实现匿名认证功能： - `AnonymousAuthenticationToken` 是
`Authentication` 接口的一个实现，用于存储适用于匿名主体的
`GrantedAuthority` 实例。 - 对应的 `AnonymousAuthenticationProvider`
会被加入到 `ProviderManager` 的认证链中，以便接受
`AnonymousAuthenticationToken` 类型的令牌。 -
最后，`AnonymousAuthenticationFilter` 位于常规认证机制之后，如果
`SecurityContextHolder` 中尚无任何 `Authentication`
对象，则该过滤器会自动添加一个 `AnonymousAuthenticationToken`。

过滤器和认证提供者的定义如下所示：

``` xml
<bean id="anonymousAuthFilter"
    class="org.springframework.security.web.authentication.AnonymousAuthenticationFilter">
<property name="key" value="foobar"/>
<property name="userAttribute" value="anonymousUser,ROLE_ANONYMOUS"/>
</bean>

<bean id="anonymousAuthenticationProvider"
    class="org.springframework.security.authentication.AnonymousAuthenticationProvider">
<property name="key" value="foobar"/>
</bean>
```

`key`
属性在过滤器和认证提供者之间共享，以确保前者创建的令牌能够被后者接受。

:::: note
::: title
:::

这里的 `key`
属性不应被视为提供了真正的安全性，它仅仅是一个用于内部匹配的记账机制。如果你在一个场景中共享了包含
`AnonymousAuthenticationProvider` 的
`ProviderManager`，并且客户端有可能自行构造 `Authentication`
对象（例如通过 RMI 调用），恶意客户端就可能提交自己创建的
`AnonymousAuthenticationToken`（包含任意用户名和权限列表）。如果这个
`key`
可被猜测或泄露，那么该令牌就会被匿名认证提供者接受。这在正常使用中不是问题，但在使用
RMI 等远程调用机制时，建议使用定制的
`ProviderManager`，并省略匿名认证提供者，而不是与 HTTP
认证机制共用同一个 `ProviderManager`。
::::

`userAttribute`
的格式为：`usernameInTheAuthenticationToken,grantedAuthority[,grantedAuthority]`。这种语法与
`InMemoryDaoImpl` 中 `userMap` 属性等号右侧所使用的语法相同。

如前所述，匿名认证的好处在于可以为所有 URI
模式统一应用安全控制，如下例所示：

``` xml
<bean id="filterSecurityInterceptor"
    class="org.springframework.security.web.access.intercept.FilterSecurityInterceptor">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="accessDecisionManager" ref="httpRequestAccessDecisionManager"/>
<property name="securityMetadata">
    <security:filter-security-metadata-source>
    <security:intercept-url pattern='/index.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/hello.htm' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/logoff.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/login.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/**' access='ROLE_USER'/>
    </security:filter-security-metadata-source>" +
</property>
</bean>
```

# AuthenticationTrustResolver {#anonymous-auth-trust-resolver}

补充匿名认证讨论的是 `AuthenticationTrustResolver` 接口及其对应的实现类
`AuthenticationTrustResolverImpl`。该接口提供了一个
`isAnonymous(Authentication)`
方法，使得感兴趣的组件可以识别这种特殊的认证状态。

`ExceptionTranslationFilter` 在处理 `AccessDeniedException`
时会使用此接口。如果抛出了
`AccessDeniedException`，且当前认证为匿名类型，过滤器不会直接返回
403（禁止访问），而是启动
`AuthenticationEntryPoint`，使用户有机会完成正常的登录流程（如表单登录、Basic
认证、Digest
认证等）。这是一个必要的区分，否则用户将始终被视为"已认证"，从而失去正常登录的机会。

在前面的拦截器配置中，我们经常看到 `ROLE_ANONYMOUS` 被替换为
`IS_AUTHENTICATED_ANONYMOUSLY`，两者在定义访问控制时效果基本相同。这是
`AuthenticatedVoter` 的一个应用示例，我们在
[授权章节](servlet/authorization/architecture.xml#authz-authenticated-voter)
中有详细介绍。`AuthenticatedVoter` 使用 `AuthenticationTrustResolver`
来解析此类配置属性，并授予匿名用户访问权限。`AuthenticatedVoter`
更加灵活，因为它允许你区分匿名用户、记住我（remember-me）用户和完全认证用户。如果你不需要这种细粒度控制，可以继续使用由
Spring Security 标准 `RoleVoter` 处理的 `ROLE_ANONYMOUS`。

# 在 Spring MVC 控制器中获取匿名认证信息 {#anonymous-auth-mvc-controller}

[Spring MVC 使用其自身的参数解析器来处理类型为 `Principal`
的参数](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-ann-arguments)。

这意味着如下代码：

::: informalexample

Java

:   ``` java
    @GetMapping("/")
    public String method(Authentication authentication) {
        if (authentication instanceof AnonymousAuthenticationToken) {
            return "anonymous";
        } else {
            return "not anonymous";
        }
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/")
    fun method(authentication: Authentication?): String {
        return if (authentication is AnonymousAuthenticationToken) {
            "anonymous"
        } else {
            "not anonymous"
        }
    }
    ```
:::

**总是返回 \"not anonymous\"**，即使是匿名请求也是如此。原因在于 Spring
MVC 是通过 `HttpServletRequest#getPrincipal`
来解析该参数的，而在匿名请求中，该方法返回 `null`。

如果你想在匿名请求中也能获取到 `Authentication` 对象，请改用
`@CurrentSecurityContext` 注解：

:::: example
::: title
使用 CurrentSecurityContext 处理匿名请求
:::

Java

:   ``` java
    @GetMapping("/")
    public String method(@CurrentSecurityContext SecurityContext context) {
        return context.getAuthentication().getName();
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/")
    fun method(@CurrentSecurityContext context : SecurityContext) : String =
            context!!.authentication!!.name
    ```
::::
