当用户首次请求一个受保护的资源时，系统会要求其提供凭据。
提示用户输入凭据最常见的方法之一是将其重定向到一个
[登录页面](servlet/authentication/passwords/form.xml)。
未认证用户请求受保护资源的简要 HTTP 交互过程可能如下所示：

:::: example
::: title
未认证用户请求受保护资源
:::

``` http
GET / HTTP/1.1
Host: example.com
Cookie: SESSION=91470ce0-3f3c-455b-b7ad-079b02290f7b
```

``` http
HTTP/1.1 302 Found
Location: /login
```
::::

随后，用户提交其用户名和密码。

:::: formalpara
::: title
提交用户名和密码
:::

``` http
POST /login HTTP/1.1
Host: example.com
Cookie: SESSION=91470ce0-3f3c-455b-b7ad-079b02290f7b

username=user&password=password&_csrf=35942e65-a172-4cd4-a1d4-d16a51147b3e
```
::::

在成功认证用户后，系统会为该用户分配一个新的会话 ID，以防止发生
[会话固定攻击](servlet/authentication/session-management.xml#ns-session-fixation)。

:::: formalpara
::: title
认证后的用户被关联到新会话
:::

``` http
HTTP/1.1 302 Found
Location: /
Set-Cookie: SESSION=4c66e474-3f5a-43ed-8e48-cc1d8cb1d1c8; Path=/; HttpOnly; SameSite=Lax
```
::::

之后的所有请求都会包含此会话
Cookie，服务器使用它来识别用户身份，并在整个会话期间完成认证。

:::: formalpara
::: title
提供已认证的会话作为凭据
:::

``` http
GET / HTTP/1.1
Host: example.com
Cookie: SESSION=4c66e474-3f5a-43ed-8e48-cc1d8cb1d1c8
```
::::

# SecurityContextRepository

在 Spring Security 中，通过
{security-api-url}org/springframework/security/web/context/SecurityContextRepository.html\[`SecurityContextRepository`\]
来实现将用户与后续请求进行关联。 `SecurityContextRepository`
的默认实现是
{security-api-url}org/springframework/security/web/context/DelegatingSecurityContextRepository.html\[`DelegatingSecurityContextRepository`\]，它会依次委派给以下组件：

- [`HttpSessionSecurityContextRepository`](#httpsecuritycontextrepository)

- [`RequestAttributeSecurityContextRepository`](#requestattributesecuritycontextrepository)

## HttpSessionSecurityContextRepository {#httpsecuritycontextrepository}

{security-api-url}org/springframework/security/web/context/HttpSessionSecurityContextRepository.html\[`HttpSessionSecurityContextRepository`\]
将
[`SecurityContext`](servlet/authentication/architecture.xml#servlet-authentication-securitycontext)
关联到 `HttpSession` 上。
如果需要以其他方式（或完全不保存）将用户与后续请求关联，开发者可以替换为其他的
`SecurityContextRepository` 实现。

## NullSecurityContextRepository

如果不希望将 `SecurityContext` 与 `HttpSession` 关联（例如在使用 OAuth
进行认证时），可以使用
{security-api-url}org/springframework/security/web/context/NullSecurityContextRepository.html\[`NullSecurityContextRepository`\]，这是一个空实现，不会执行任何操作。

## RequestAttributeSecurityContextRepository

{security-api-url}org/springframework/security/web/context/RequestAttributeSecurityContextRepository.html\[`RequestAttributeSecurityContextRepository`\]
将 `SecurityContext` 保存为请求属性（request
attribute），确保即使在跨多个分发类型（dispatch
types）的单个请求中，`SecurityContext` 也不会丢失。

例如，假设客户端发起请求并完成认证，但随后发生了错误。根据 Servlet
容器的具体实现，错误处理可能导致之前建立的 `SecurityContext`
被清除，然后触发错误分发（error
dispatch）。此时，在错误分发过程中，`SecurityContext`
已不存在，导致错误页面无法获取当前用户信息或进行授权判断，除非
`SecurityContext` 被某种方式保留下来。

:::: example
::: title
Use RequestAttributeSecurityContextRepository
:::

Java

:   ``` java
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
            // ...
            .securityContext((securityContext) -> securityContext
                .securityContextRepository(new RequestAttributeSecurityContextRepository())
            );
        return http.build();
    }
    ```

XML

:   ``` xml
    <http security-context-repository-ref="contextRepository">
        <!-- ... -->
    </http>
    <b:bean name="contextRepository"
        class="org.springframework.security.web.context.RequestAttributeSecurityContextRepository" />
    ```
::::

## DelegatingSecurityContextRepository

{security-api-url}org/springframework/security/web/context/DelegatingSecurityContextRepository.html\[`DelegatingSecurityContextRepository`\]
可将 `SecurityContext` 同时保存到多个 `SecurityContextRepository`
委托对象中，并允许按指定顺序从中读取。

最常用的配置示例如下，它允许同时使用
[`RequestAttributeSecurityContextRepository`](#requestattributesecuritycontextrepository)
和
[`HttpSessionSecurityContextRepository`](#httpsecuritycontextrepository)。

:::: example
::: title
Configure DelegatingSecurityContextRepository
:::

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ...
            .securityContext((securityContext) -> securityContext
                .securityContextRepository(new DelegatingSecurityContextRepository(
                    new RequestAttributeSecurityContextRepository(),
                    new HttpSessionSecurityContextRepository()
                ))
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            // ...
            securityContext {
                securityContextRepository = DelegatingSecurityContextRepository(
                    RequestAttributeSecurityContextRepository(),
                    HttpSessionSecurityContextRepository()
                )
            }
        }
        return http.build()
    }
    ```

XML

:   ``` xml
    <http security-context-repository-ref="contextRepository">
        <!-- ... -->
    </http>
    <bean name="contextRepository"
        class="org.springframework.security.web.context.DelegatingSecurityContextRepository">
            <constructor-arg>
                <bean class="org.springframework.security.web.context.RequestAttributeSecurityContextRepository" />
            </constructor-arg>
            <constructor-arg>
                <bean class="org.springframework.security.web.context.HttpSessionSecurityContextRepository" />
            </constructor-arg>
    </bean>
    ```
::::

:::: note
::: title
:::

在 Spring Security 6 中，上述示例即为默认配置。
::::

# SecurityContextPersistenceFilter

{security-api-url}org/springframework/security/web/context/SecurityContextPersistenceFilter.html\[`SecurityContextPersistenceFilter`\]
负责在请求之间通过
[`SecurityContextRepository`](:servlet/authentication/persistence.xml#securitycontextrepository)
持久化 `SecurityContext`。

![securitycontextpersistencefilter](servlet/authentication/securitycontextpersistencefilter.png)

![number 1]({icondir}/number_1.png)
在运行应用程序其余部分之前，`SecurityContextPersistenceFilter` 从
`SecurityContextRepository` 加载 `SecurityContext` 并设置到
`SecurityContextHolder` 中。

![number 2]({icondir}/number_2.png) 接着执行应用程序逻辑。

![number 3]({icondir}/number_3.png) 最后，如果 `SecurityContext`
发生了变化，则使用 `SecurityContextPersistenceRepository` 保存它。
这意味着，只要设置了
`SecurityContextHolder`，`SecurityContextPersistenceFilter` 就能确保
`SecurityContext` 被自动持久化。

但在某些情况下，响应可能在 `SecurityContextPersistenceFilter`
执行完成前就已经提交并发送给客户端。
例如，如果向客户端发送了一个重定向响应，那么响应会被立即写回客户端。这会导致第
3 步无法创建新的 `HttpSession`，因为会话 ID
无法添加到已经发出的响应头中。 另一种情况是：如果客户端成功认证，但在
`SecurityContextPersistenceFilter`
完成前响应已被提交，而客户端紧接着发起了第二个请求，这时第二个请求可能会使用错误的认证上下文。

为了避免这些问题，`SecurityContextPersistenceFilter` 会对
`HttpServletRequest` 和 `HttpServletResponse` 进行包装，用于检测
`SecurityContext` 是否发生变化，并在响应即将提交前及时保存更新后的
`SecurityContext`。

# SecurityContextHolderFilter

{security-api-url}org/springframework/security/web/context/SecurityContextHolderFilter.html\[`SecurityContextHolderFilter`\]
负责在请求之间通过
[`SecurityContextRepository`](:servlet/authentication/persistence.xml#securitycontextrepository)
加载 `SecurityContext`。

![securitycontextholderfilter](servlet/authentication/securitycontextholderfilter.png)

![number 1]({icondir}/number_1.png)
在运行应用程序其余部分之前，`SecurityContextHolderFilter` 从
`SecurityContextRepository` 加载 `SecurityContext` 并设置到
`SecurityContextHolder`。

![number 2]({icondir}/number_2.png) 接着执行应用程序逻辑。

与
[`SecurityContextPersistenceFilter`](servlet/authentication/persistence.xml#securitycontextpersistencefilter)
不同的是，`SecurityContextHolderFilter` 仅负责加载
`SecurityContext`，并不负责保存它。 因此，当使用
`SecurityContextHolderFilter` 时，必须显式地保存 `SecurityContext`。

Unresolved directive in persistence.adoc.zhCN -
include::partial\$servlet/architecture/security-context-explicit.adoc\[\]
