# 内省的最小依赖 {#oauth2resourceserver-opaque-minimaldependencies}

如 [JWT
的最小依赖](servlet/oauth2/resource-server/jwt.xml#oauth2resourceserver-jwt-minimaldependencies)
所述，大多数资源服务器支持都收集在
`spring-security-oauth2-resource-server` 中。 但是，除非提供了自定义的
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-introspector)，否则资源服务器将回退到
`NimbusOpaqueTokenIntrospector`。 这意味着
`spring-security-oauth2-resource-server` 和 `oauth2-oidc-sdk`
都是拥有一个支持不透明 Bearer 令牌的工作最小资源服务器所必需的。 请参考
`spring-security-oauth2-resource-server` 来确定 `oauth2-oidc-sdk`
的正确版本。

# 内省的最小配置 {#oauth2resourceserver-opaque-minimalconfiguration}

通常情况下，可以通过由授权服务器托管的 [OAuth 2.0
内省端点](https://tools.ietf.org/html/rfc7662) 来验证不透明令牌。
当撤销是一个需求时，这可能非常方便。

使用 [Spring Boot](https://spring.io/projects/spring-boot)
时，将应用程序配置为使用内省的资源服务器包括两个基本步骤。
首先，包含所需的依赖项；其次，指示内省端点的详细信息。

## 指定授权服务器 {#oauth2resourceserver-opaque-introspectionuri}

要指定内省端点的位置，只需执行以下操作：

``` yaml
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          introspection-uri: https://idp.example.com/introspect
          client-id: client
          client-secret: secret
```

其中 `https://idp.example.com/introspect`
是您的授权服务器托管的内省端点，而 `client-id` 和 `client-secret`
是访问该端点所需的凭据。

资源服务器将使用这些属性进一步自我配置，并随后验证传入的 JWT。

:::: note
::: title
:::

使用内省时，授权服务器的话语权是决定性的。
如果授权服务器响应说令牌有效，那么它就是有效的。
::::

就这样！

## 启动预期 {#_启动预期}

当使用此属性和这些依赖项时，资源服务器会自动配置自身以验证不透明的
Bearer 令牌。

这个启动过程比 JWT
简单得多，因为不需要发现任何端点，也不需要添加额外的验证规则。

## 运行时预期 {#_运行时预期}

一旦应用程序启动，资源服务器将尝试处理任何包含 `Authorization: Bearer`
头的请求：

``` http
GET / HTTP/1.1
Authorization: Bearer some-token-value # 资源服务器将处理此请求
```

只要指定了这种方案，资源服务器就会根据 Bearer 令牌规范尝试处理请求。

对于一个不透明令牌，资源服务器将：

1.  使用提供的凭据和令牌查询所提供的内省端点

2.  检查响应中是否存在 `{ 'active' : true }` 属性

3.  将每个作用域映射为带有前缀 `SCOPE_` 的权限

默认情况下，生成的 `Authentication#getPrincipal` 是 Spring Security 的
{security-api-url}org/springframework/security/oauth2/core/OAuth2AuthenticatedPrincipal.html\[OAuth2AuthenticatedPrincipal\]
对象，而 `Authentication#getName` 映射到令牌的 `sub` 属性（如果存在）。

接下来，您可能想要跳转到：

- [不透明令牌认证的工作原理](#oauth2resourceserver-opaque-architecture)

- [认证后查找属性](#oauth2resourceserver-opaque-attributes)

- [手动提取权限](#oauth2resourceserver-opaque-authorization-extraction)

- [使用 JWT 的内省](#oauth2resourceserver-opaque-jwt-introspector)

# 不透明令牌认证的工作原理 {#oauth2resourceserver-opaque-architecture}

接下来，让我们看看 Spring Security 在基于 Servlet 的应用程序中用于支持
[不透明令牌](https://tools.ietf.org/html/rfc7662)
认证的架构组件，就像我们刚才看到的那个一样。

{security-api-url}org/springframework/security/oauth2/server/resource/authentication/OpaqueTokenAuthenticationProvider.html\[`OpaqueTokenAuthenticationProvider`\]
是一个
[`AuthenticationProvider`](servlet/authentication/architecture.xml#servlet-authentication-authenticationprovider)
实现，它利用了一个
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-introspector)
来认证一个不透明令牌。

让我们来看看 `OpaqueTokenAuthenticationProvider` 在 Spring Security
中是如何工作的。 下图解释了 [读取 Bearer
令牌](servlet/oauth2/resource-server/index.xml#oauth2resourceserver-authentication-bearertokenauthenticationfilter)
图中的
[`AuthenticationManager`](servlet/authentication/architecture.xml#servlet-authentication-authenticationmanager)
的工作细节。

<figure>
<img src="servlet/oauth2/opaquetokenauthenticationprovider.png"
alt="opaquetokenauthenticationprovider" />
<figcaption><code>OpaqueTokenAuthenticationProvider</code>
使用方法</figcaption>
</figure>

![number 1]({icondir}/number_1.png) 来自 [读取 Bearer
令牌](servlet/oauth2/resource-server/index.xml#oauth2resourceserver-authentication-bearertokenauthenticationfilter)
的认证 `Filter` 将一个 `BearerTokenAuthenticationToken` 传递给
`AuthenticationManager`，后者由
[`ProviderManager`](servlet/authentication/architecture.xml#servlet-authentication-providermanager)
实现。

![number 2]({icondir}/number_2.png) `ProviderManager`
被配置为使用一种类型为 `OpaqueTokenAuthenticationProvider` 的
[AuthenticationProvider](servlet/authentication/architecture.xml#servlet-authentication-authenticationprovider)。

![number 3]({icondir}/number_3.png) `OpaqueTokenAuthenticationProvider`
使用
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-introspector)
对不透明令牌进行内省并添加授予的权限。 当认证成功时，返回的
[`Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
是 `BearerTokenAuthentication` 类型，并且其主体是由配置的
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-introspector)
返回的 `OAuth2AuthenticatedPrincipal`。 最终，返回的
`BearerTokenAuthentication` 将由认证 `Filter` 设置到
[`SecurityContextHolder`](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
中。

# 认证后查找属性 {#oauth2resourceserver-opaque-attributes}

一旦令牌被认证，`BearerTokenAuthentication` 的实例将被设置在
`SecurityContext` 中。

这意味着在您的配置中使用 `@EnableWebMvc` 时，可以在 `@Controller`
方法中使用它：

::: informalexample

Java

:   ``` java
    @GetMapping("/foo")
    public String foo(BearerTokenAuthentication authentication) {
        return authentication.getTokenAttributes().get("sub") + " 是主题";
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/foo")
    fun foo(authentication: BearerTokenAuthentication): String {
        return authentication.tokenAttributes["sub"].toString() + " 是主题"
    }
    ```
:::

由于 `BearerTokenAuthentication` 包含一个
`OAuth2AuthenticatedPrincipal`，这也意味着它可以用于控制器方法中：

::: informalexample

Java

:   ``` java
    @GetMapping("/foo")
    public String foo(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        return principal.getAttribute("sub") + " 是主题";
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/foo")
    fun foo(@AuthenticationPrincipal principal: OAuth2AuthenticatedPrincipal): String {
        return principal.getAttribute<Any>("sub").toString() + " 是主题"
    }
    ```
:::

## 通过 SpEL 查找属性 {#_通过_spel_查找属性}

当然，这也意味着可以通过 SpEL 访问属性。

例如，如果使用 `@EnableGlobalMethodSecurity` 以便可以使用
`@PreAuthorize` 注解，您可以这样做：

::: informalexample

Java

:   ``` java
    @PreAuthorize("principal?.attributes['sub'] == 'foo'")
    public String forFoosEyesOnly() {
        return "foo";
    }
    ```

Kotlin

:   ``` kotlin
    @PreAuthorize("principal?.attributes['sub'] == 'foo'")
    fun forFoosEyesOnly(): String {
        return "foo"
    }
    ```
:::

# 覆盖或替换 Boot 自动配置 {#oauth2resourceserver-opaque-sansboot}

Spring Boot 为资源服务器生成了两个 `@Bean`。

第一个是配置应用为资源服务器的
`SecurityFilterChain`。当使用不透明令牌时，此 `SecurityFilterChain`
看起来像这样：

:::: example
::: title
默认不透明令牌配置
:::

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize(anyRequest, authenticated)
            }
            oauth2ResourceServer {
                opaqueToken { }
            }
        }
        return http.build()
    }
    ```
::::

如果应用程序没有暴露 `SecurityFilterChain` bean，则 Spring Boot
将暴露上述默认值。

替换这个只需要在应用程序中暴露该 bean：

:::: example
::: title
自定义不透明令牌配置
:::

Java

:   ``` java
    import static org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers.hasScope;

    @Configuration
    @EnableWebSecurity
    public class MyCustomSecurityConfiguration {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/messages/**").access(hasScope("message:read"))
                    .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                    .opaqueToken(opaqueToken -> opaqueToken
                        .introspector(myIntrospector())
                    )
                );
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers.hasScope;

    @Configuration
    @EnableWebSecurity
    class MyCustomSecurityConfiguration {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize("/messages/**", hasScope("SCOPE_message:read"))
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken {
                        introspector = myIntrospector()
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

上述代码要求所有以 `/messages/` 开头的 URL 必须具有 `message:read`
的作用域。

`oauth2ResourceServer` DSL 上的方法也可以覆盖或替换自动配置。

例如，Spring Boot 创建的第二个 `@Bean` 是
`OpaqueTokenIntrospector`，[它将 `String` 令牌解码成经过验证的
`OAuth2AuthenticatedPrincipal`
实例](#oauth2resourceserver-opaque-architecture-introspector)：

::: informalexample

Java

:   ``` java
    @Bean
    public OpaqueTokenIntrospector introspector() {
        return new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun introspector(): OpaqueTokenIntrospector {
        return NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret)
    }
    ```
:::

如果应用程序未暴露
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)
bean，则 Spring Boot 将暴露上述默认值。

并且其配置可以通过 `introspectionUri()` 和
`introspectionClientCredentials()` 覆盖，或者通过 `introspector()`
替换。

如果应用程序未暴露 `OpaqueTokenAuthenticationConverter` bean，则
spring-security 将构建 `BearerTokenAuthentication`。

或者，如果您完全不使用 Spring
Boot，则所有这些组件------过滤器链、[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)
和 `OpaqueTokenAuthenticationConverter` 都可以在 XML 中指定。

过滤器链如下所示指定：

:::: example
::: title
默认不透明令牌配置
:::

Xml

:   ``` xml
    <http>
        <intercept-uri pattern="/**" access="authenticated"/>
        <oauth2-resource-server>
            <opaque-token introspector-ref="opaqueTokenIntrospector"
                    authentication-converter-ref="opaqueTokenAuthenticationConverter"/>
        </oauth2-resource-server>
    </http>
    ```
::::

以及
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)
如下所示：

:::: example
::: title
不透明令牌内省器
:::

Xml

:   ``` xml
    <bean id="opaqueTokenIntrospector"
            class="org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector">
        <constructor-arg value="${spring.security.oauth2.resourceserver.opaquetoken.introspection_uri}"/>
        <constructor-arg value="${spring.security.oauth2.resourceserver.opaquetoken.client_id}"/>
        <constructor-arg value="${spring.security.oauth2.resourceserver.opaquetoken.client_secret}"/>
    </bean>
    ```
::::

以及 `OpaqueTokenAuthenticationConverter` 如下所示：

:::: example
::: title
不透明令牌认证转换器
:::

Xml

:   ``` xml
    <bean id="opaqueTokenAuthenticationConverter"
            class="com.example.CustomOpaqueTokenAuthenticationConverter"/>
    ```
::::

## 使用 `introspectionUri()` {#oauth2resourceserver-opaque-introspectionuri-dsl}

授权服务器的内省 Uri
可以作为配置属性[进行配置](#oauth2resourceserver-opaque-introspectionuri)，也可以在
DSL 中提供：

:::: example
::: title
内省 URI 配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class DirectlyConfiguredIntrospectionUri {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                    .opaqueToken(opaqueToken -> opaqueToken
                        .introspectionUri("https://idp.example.com/introspect")
                        .introspectionClientCredentials("client", "secret")
                    )
                );
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class DirectlyConfiguredIntrospectionUri {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken {
                        introspectionUri = "https://idp.example.com/introspect"
                        introspectionClientCredentials("client", "secret")
                    }
                }
            }
            return http.build()
        }
    }
    ```

Xml

:   ``` xml
    <bean id="opaqueTokenIntrospector"
            class="org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector">
        <constructor-arg value="https://idp.example.com/introspect"/>
        <constructor-arg value="client"/>
        <constructor-arg value="secret"/>
    </bean>
    ```
::::

使用 `introspectionUri()` 优先于任何配置属性。

## 使用 `introspector()` {#oauth2resourceserver-opaque-introspector-dsl}

比 `introspectionUri()` 更强大的是 `introspector()`，它将完全替换任何
Boot 自动配置的
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)：

:::: example
::: title
内省器配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class DirectlyConfiguredIntrospector {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                    .opaqueToken(opaqueToken -> opaqueToken
                        .introspector(myCustomIntrospector())
                    )
                );
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class DirectlyConfiguredIntrospector {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken {
                        introspector = myCustomIntrospector()
                    }
                }
            }
            return http.build()
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-uri pattern="/**" access="authenticated"/>
        <oauth2-resource-server>
            <opaque-token introspector-ref="myCustomIntrospector"/>
        </oauth2-resource-server>
    </http>
    ```
::::

当需要更深层次的配置时，比如
[权限映射](#oauth2resourceserver-opaque-authorization-extraction)、[JWT
撤销](#oauth2resourceserver-opaque-jwt-introspector) 或
[请求超时](#oauth2resourceserver-opaque-timeouts)，这非常有用。

## 暴露 `OpaqueTokenIntrospector` `@Bean` {#oauth2resourceserver-opaque-introspector-bean}

或者，暴露一个
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)
`@Bean` 与使用 `introspector()` 效果相同：

``` java
@Bean
public OpaqueTokenIntrospector introspector() {
    return new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
}
```

# 配置授权 {#oauth2resourceserver-opaque-authorization}

OAuth 2.0 内省端点通常会返回一个 `scope`
属性，表示已授予的作用域（或权限），例如：

`{ …​, "scope" : "messages contacts"}`

在这种情况下，资源服务器将尝试将这些作用域强制转换为授予权限列表，并为每个作用域加上字符串
\"SCOPE\_\" 前缀。

这意味着要保护从不透明令牌派生出的作用域的端点或方法，相应的表达式应包含此前缀：

:::: example
::: title
授权不透明令牌配置
:::

Java

:   ``` java
    import static org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers.hasScope;

    @Configuration
    @EnableWebSecurity
    public class MappedAuthorities {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                    .requestMatchers("/contacts/**").access(hasScope("contacts"))
                    .requestMatchers("/messages/**").access(hasScope("messages"))
                    .anyRequest().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers.hasScope

    @Configuration
    @EnableWebSecurity
    class MappedAuthorities {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
           http {
                authorizeRequests {
                    authorize("/contacts/**", hasScope("contacts"))
                    authorize("/messages/**", hasScope("messages"))
                    authorize(anyRequest, authenticated)
                }
               oauth2ResourceServer {
                   opaqueToken { }
               }
            }
            return http.build()
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <intercept-uri pattern="/contacts/**" access="hasAuthority('SCOPE_contacts')"/>
        <intercept-uri pattern="/messages/**" access="hasAuthority('SCOPE_messages')"/>
        <oauth2-resource-server>
            <opaque-token introspector-ref="opaqueTokenIntrospector"/>
        </oauth2-resource-server>
    </http>
    ```
::::

或者类似地使用方法安全性：

::: informalexample

Java

:   ``` java
    @PreAuthorize("hasAuthority('SCOPE_messages')")
    public List<Message> getMessages(...) {}
    ```

Kotlin

:   ``` kotlin
    @PreAuthorize("hasAuthority('SCOPE_messages')")
    fun getMessages(): List<Message?> {}
    ```
:::

## 手动提取权限 {#oauth2resourceserver-opaque-authorization-extraction}

默认情况下，不透明令牌支持将从内省响应中提取作用域声明，并将其解析为单独的
`GrantedAuthority` 实例。

例如，如果内省响应是：

``` json
{
    "active" : true,
    "scope" : "message:read message:write"
}
```

那么资源服务器将生成一个包含两个权限的 `Authentication`，一个对应
`message:read`，另一个对应 `message:write`。

当然，这可以通过使用自定义的
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)
来定制，该内省器查看属性集并以自己的方式转换：

::: informalexample

Java

:   ``` java
    public class CustomAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
        private OpaqueTokenIntrospector delegate =
                new NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret");

        public OAuth2AuthenticatedPrincipal introspect(String token) {
            OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
            return new DefaultOAuth2AuthenticatedPrincipal(
                    principal.getName(), principal.getAttributes(), extractAuthorities(principal));
        }

        private Collection<GrantedAuthority> extractAuthorities(OAuth2AuthenticatedPrincipal principal) {
            List<String> scopes = principal.getAttribute(OAuth2IntrospectionClaimNames.SCOPE);
            return scopes.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
    }
    ```

Kotlin

:   ``` kotlin
    class CustomAuthoritiesOpaqueTokenIntrospector : OpaqueTokenIntrospector {
        private val delegate: OpaqueTokenIntrospector = NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret")
        override fun introspect(token: String): OAuth2AuthenticatedPrincipal {
            val principal: OAuth2AuthenticatedPrincipal = delegate.introspect(token)
            return DefaultOAuth2AuthenticatedPrincipal(
                    principal.name, principal.attributes, extractAuthorities(principal))
        }

        private fun extractAuthorities(principal: OAuth2AuthenticatedPrincipal): Collection<GrantedAuthority> {
            val scopes: List<String> = principal.getAttribute(OAuth2IntrospectionClaimNames.SCOPE)
            return scopes
                    .map { SimpleGrantedAuthority(it) }
        }
    }
    ```
:::

此后，只需将其暴露为 `@Bean` 即可配置此自定义内省器：

::: informalexample

Java

:   ``` java
    @Bean
    public OpaqueTokenIntrospector introspector() {
        return new CustomAuthoritiesOpaqueTokenIntrospector();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun introspector(): OpaqueTokenIntrospector {
        return CustomAuthoritiesOpaqueTokenIntrospector()
    }
    ```
:::

# 配置超时 {#oauth2resourceserver-opaque-timeouts}

默认情况下，资源服务器与授权服务器协调时使用 30 秒的连接和套接字超时。

在某些场景下这可能太短了。此外，它不考虑更复杂的模式，如退避和发现。

为了调整资源服务器连接到授权服务器的方式，`NimbusOpaqueTokenIntrospector`
接受一个 `RestOperations` 实例：

::: informalexample

Java

:   ``` java
    @Bean
    public OpaqueTokenIntrospector introspector(RestTemplateBuilder builder, OAuth2ResourceServerProperties properties) {
        RestOperations rest = builder
                .basicAuthentication(properties.getOpaquetoken().getClientId(), properties.getOpaquetoken().getClientSecret())
                .setConnectTimeout(Duration.ofSeconds(60))
                .setReadTimeout(Duration.ofSeconds(60))
                .build();

        return new NimbusOpaqueTokenIntrospector(introspectionUri, rest);
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun introspector(builder: RestTemplateBuilder, properties: OAuth2ResourceServerProperties): OpaqueTokenIntrospector? {
        val rest: RestOperations = builder
                .basicAuthentication(properties.opaquetoken.clientId, properties.opaquetoken.clientSecret)
                .setConnectTimeout(Duration.ofSeconds(60))
                .setReadTimeout(Duration.ofSeconds(60))
                .build()
        return NimbusOpaqueTokenIntrospector(introspectionUri, rest)
    }
    ```
:::

# 使用内省处理 JWT {#oauth2resourceserver-opaque-jwt-introspector}

一个常见的问题是内省是否与 JWT 兼容。 Spring Security
的不透明令牌支持设计为不关心令牌的格式------它乐意将任何令牌传递给提供的内省端点。

因此，假设您有一个要求，即每次请求都需要检查授权服务器，以防 JWT
已被撤销。

即使您使用的是 JWT
格式的令牌，您的验证方法也是内省，这意味着您希望这样做：

``` yaml
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          introspection-uri: https://idp.example.org/introspection
          client-id: client
          client-secret: secret
```

在这种情况下，生成的 `Authentication` 将是 `BearerTokenAuthentication`。
相应 `OAuth2AuthenticatedPrincipal`
中的任何属性都将由内省端点返回的内容决定。

但假设奇怪的是，内省端点只返回令牌是否处于活动状态。 现在该怎么办？

在这种情况下，您可以创建一个自定义的
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)，仍然调用端点，然后更新返回的主体使其具有
JWT 的声明作为属性：

::: informalexample

Java

:   ``` java
    public class JwtOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
        private OpaqueTokenIntrospector delegate =
                new NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret");
        private JwtDecoder jwtDecoder = new NimbusJwtDecoder(new ParseOnlyJWTProcessor());

        public OAuth2AuthenticatedPrincipal introspect(String token) {
            OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
            try {
                Jwt jwt = this.jwtDecoder.decode(token);
                return new DefaultOAuth2AuthenticatedPrincipal(jwt.getClaims(), NO_AUTHORITIES);
            } catch (JwtException ex) {
                throw new OAuth2IntrospectionException(ex);
            }
        }

        private static class ParseOnlyJWTProcessor extends DefaultJWTProcessor<SecurityContext> {
            JWTClaimsSet process(SignedJWT jwt, SecurityContext context)
                    throws JOSEException {
                return jwt.getJWTClaimsSet();
            }
        }
    }
    ```

Kotlin

:   ``` kotlin
    class JwtOpaqueTokenIntrospector : OpaqueTokenIntrospector {
        private val delegate: OpaqueTokenIntrospector = NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret")
        private val jwtDecoder: JwtDecoder = NimbusJwtDecoder(ParseOnlyJWTProcessor())
        override fun introspect(token: String): OAuth2AuthenticatedPrincipal {
            val principal = delegate.introspect(token)
            return try {
                val jwt: Jwt = jwtDecoder.decode(token)
                DefaultOAuth2AuthenticatedPrincipal(jwt.claims, NO_AUTHORITIES)
            } catch (ex: JwtException) {
                throw OAuth2IntrospectionException(ex.message)
            }
        }

        private class ParseOnlyJWTProcessor : DefaultJWTProcessor<SecurityContext>() {
            override fun process(jwt: SignedJWT, context: SecurityContext): JWTClaimsSet {
                return jwt.jwtClaimsSet
            }
        }
    }
    ```
:::

此后，只需将其暴露为 `@Bean` 即可配置此自定义内省器：

::: informalexample

Java

:   ``` java
    @Bean
    public OpaqueTokenIntrospector introspector() {
        return new JwtOpaqueTokenIntrospector();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun introspector(): OpaqueTokenIntrospector {
        return JwtOpaqueTokenIntrospector()
    }
    ```
:::

# 调用 `/userinfo` 端点 {#oauth2resourceserver-opaque-userinfo}

一般来说，资源服务器并不关心底层用户，而是关心已被授予的权限。

尽管如此，在某些时候将授权声明与用户关联起来可能是有价值的。

如果应用程序同时使用
`spring-security-oauth2-client`，并且已经设置了适当的
`ClientRegistrationRepository`，那么通过自定义
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)
就很简单了。 下面的实现做了三件事：

- 委托给内省端点，以确认令牌的有效性

- 查找与 `/userinfo` 端点相关联的适当客户端注册

- 调用并返回来自 `/userinfo` 端点的响应

::: informalexample

Java

:   ``` java
    public class UserInfoOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
        private final OpaqueTokenIntrospector delegate =
                new NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret");
        private final OAuth2UserService oauth2UserService = new DefaultOAuth2UserService();

        private final ClientRegistrationRepository repository;

        // ... 构造函数

        @Override
        public OAuth2AuthenticatedPrincipal introspect(String token) {
            OAuth2AuthenticatedPrincipal authorized = this.delegate.introspect(token);
            Instant issuedAt = authorized.getAttribute(ISSUED_AT);
            Instant expiresAt = authorized.getAttribute(EXPIRES_AT);
            ClientRegistration clientRegistration = this.repository.findByRegistrationId("registration-id");
            OAuth2AccessToken token = new OAuth2AccessToken(BEARER, token, issuedAt, expiresAt);
            OAuth2UserRequest oauth2UserRequest = new OAuth2UserRequest(clientRegistration, token);
            return this.oauth2UserService.loadUser(oauth2UserRequest);
        }
    }
    ```

Kotlin

:   ``` kotlin
    class UserInfoOpaqueTokenIntrospector : OpaqueTokenIntrospector {
        private val delegate: OpaqueTokenIntrospector = NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret")
        private val oauth2UserService = DefaultOAuth2UserService()
        private val repository: ClientRegistrationRepository? = null

        // ... 构造函数

        override fun introspect(token: String): OAuth2AuthenticatedPrincipal {
            val authorized = delegate.introspect(token)
            val issuedAt: Instant? = authorized.getAttribute(ISSUED_AT)
            val expiresAt: Instant? = authorized.getAttribute(EXPIRES_AT)
            val clientRegistration: ClientRegistration = repository!!.findByRegistrationId("registration-id")
            val accessToken = OAuth2AccessToken(BEARER, token, issuedAt, expiresAt)
            val oauth2UserRequest = OAuth2UserRequest(clientRegistration, accessToken)
            return oauth2UserService.loadUser(oauth2UserRequest)
        }
    }
    ```
:::

如果您不使用 `spring-security-oauth2-client`，也同样很简单。
您只需用自己的 `WebClient` 实例调用 `/userinfo`：

::: informalexample

Java

:   ``` java
    public class UserInfoOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
        private final OpaqueTokenIntrospector delegate =
                new NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret");
        private final WebClient rest = WebClient.create();

        @Override
        public OAuth2AuthenticatedPrincipal introspect(String token) {
            OAuth2AuthenticatedPrincipal authorized = this.delegate.introspect(token);
            return makeUserInfoRequest(authorized);
        }
    }
    ```

Kotlin

:   ``` kotlin
    class UserInfoOpaqueTokenIntrospector : OpaqueTokenIntrospector {
        private val delegate: OpaqueTokenIntrospector = NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret")
        private val rest: WebClient = WebClient.create()

        override fun introspect(token: String): OAuth2AuthenticatedPrincipal {
            val authorized = delegate.introspect(token)
            return makeUserInfoRequest(authorized)
        }
    }
    ```
:::

无论哪种方式，创建了您的
[`OpaqueTokenIntrospector`](#oauth2resourceserver-opaque-architecture-introspector)
后，您应该将其发布为 `@Bean` 以覆盖默认设置：

::: informalexample

Java

:   ``` java
    @Bean
    OpaqueTokenIntrospector introspector() {
        return new UserInfoOpaqueTokenIntrospector(...);
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun introspector(): OpaqueTokenIntrospector {
        return UserInfoOpaqueTokenIntrospector(...)
    }
    ```
:::
