Spring Security 对 RSocket 的支持依赖于
`SocketAcceptorInterceptor`。安全机制的主要入口是
`PayloadSocketAcceptorInterceptor`，它适配了 RSocket 的 API，允许使用
`PayloadInterceptor` 实现来拦截 `PayloadExchange`。

以下是一个最小化的 RSocket 安全配置示例：

- Hello RSocket
  {gh-samples-url}/reactive/rsocket/hello-security\[hellorsocket\]

- [Spring
  Flights](https://github.com/rwinch/spring-flights/tree/security)

# 最小化 RSocket 安全配置 {#_最小化_rsocket_安全配置}

你可以在下面找到一个最小化的 RSocket 安全配置：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableRSocketSecurity
    public class HelloRSocketSecurityConfig {

        @Bean
        public MapReactiveUserDetailsService userDetailsService() {
            UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER")
                .build();
            return new MapReactiveUserDetailsService(user);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableRSocketSecurity
    open class HelloRSocketSecurityConfig {
        @Bean
        open fun userDetailsService(): MapReactiveUserDetailsService {
            val user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER")
                .build()
            return MapReactiveUserDetailsService(user)
        }
    }
    ```
:::

该配置启用了 [简单认证](#rsocket-authentication-simple)，并设置了
[rsocket
授权](#rsocket-authorization)，要求所有请求都必须经过身份验证的用户才能访问。

# 添加 SecuritySocketAcceptorInterceptor {#_添加_securitysocketacceptorinterceptor}

为了让 Spring Security 正常工作，我们需要将
`SecuritySocketAcceptorInterceptor` 应用于
`ServerRSocketFactory`。这样可以将我们的
`PayloadSocketAcceptorInterceptor` 与 RSocket 基础设施连接起来。

当你包含正确的依赖项时，Spring Boot 会自动在
`RSocketSecurityAutoConfiguration`
中注册该拦截器：{gh-samples-url}/reactive/rsocket/hello-security/build.gradle。

或者，如果你不使用 Boot 的自动配置，则可以手动注册如下：

::: informalexample

Java

:   ``` java
    @Bean
    RSocketServerCustomizer springSecurityRSocketSecurity(SecuritySocketAcceptorInterceptor interceptor) {
        return (server) -> server.interceptors((registry) -> registry.forSocketAcceptor(interceptor));
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun springSecurityRSocketSecurity(interceptor: SecuritySocketAcceptorInterceptor): RSocketServerCustomizer {
        return RSocketServerCustomizer { server ->
            server.interceptors { registry ->
                registry.forSocketAcceptor(interceptor)
            }
        }
    }
    ```
:::

要自定义拦截器本身，请使用 `RSocketSecurity` 来添加
[认证](#rsocket-authentication) 和 [授权](#rsocket-authorization) 规则。

# RSocket 认证 {#rsocket-authentication}

RSocket 认证通过 `AuthenticationPayloadInterceptor`
执行，它充当控制器以调用 `ReactiveAuthenticationManager` 实例。

## 连接建立时与请求时的认证 {#rsocket-authentication-setup-vs-request}

通常，认证可以在连接建立（setup）时、请求时或两者同时进行。

在某些场景中，在连接建立时进行认证是有意义的。常见的情况是单个用户（如移动设备连接）使用一个
RSocket
连接。在这种情况下，只有一个用户使用此连接，因此可以在连接时一次性完成认证。

当 RSocket
连接被多个用户共享时，在每个请求中发送凭证更有意义。例如，一个作为下游服务连接到
RSocket 服务器的 Web
应用程序可能只建立一个连接供所有用户使用。此时，如果 RSocket
服务器需要根据 Web 应用用户的凭据执行授权，则应在每次请求时进行认证。

在某些情况下，既在连接建立时又在每次请求时进行认证是有意义的。以前面描述的
Web 应用为例：如果我们需要限制仅允许该 Web
应用本身建立连接，可以在连接时提供具有 `SETUP`
权限的凭证；而各个最终用户可以拥有不同的权限但不具备 `SETUP`
权限。这意味着普通用户可以发起请求，但不能创建新的连接。

## 简单认证 {#rsocket-authentication-simple}

Spring Security 支持 [Simple Authentication Metadata
Extension](https://github.com/rsocket/rsocket/blob/5920ed374d008abb712cb1fd7c9d91778b2f4a68/Extensions/Security/Simple.md)。

:::: note
::: title
:::

基本认证（Basic Authentication）已演进为简单认证（Simple
Authentication），仅为了向后兼容而保留支持。可通过
`RSocketSecurity.basicAuthentication(Customizer)` 方法进行配置。
::::

RSocket 接收方可通过 `AuthenticationPayloadExchangeConverter`
解码凭证，该转换器会由 DSL 中的 `simpleAuthentication`
部分自动配置。以下示例展示了显式配置方式：

::: informalexample

Java

:   ``` java
    @Bean
    PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
        rsocket
            .authorizePayload(authorize ->
                authorize
                        .anyRequest().authenticated()
                        .anyExchange().permitAll()
            )
            .simpleAuthentication(Customizer.withDefaults());
        return rsocket.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun rsocketInterceptor(rsocket: RSocketSecurity): PayloadSocketAcceptorInterceptor {
        rsocket
            .authorizePayload { authorize -> authorize
                    .anyRequest().authenticated()
                    .anyExchange().permitAll()
            }
            .simpleAuthentication(withDefaults())
        return rsocket.build()
    }
    ```
:::

RSocket 发送方可以通过 `SimpleAuthenticationEncoder`
发送凭证，你可以将其添加到 Spring 的 `RSocketStrategies` 中。

::: informalexample

Java

:   ``` java
    RSocketStrategies.Builder strategies = ...;
    strategies.encoder(new SimpleAuthenticationEncoder());
    ```

Kotlin

:   ``` kotlin
    var strategies: RSocketStrategies.Builder = ...
    strategies.encoder(SimpleAuthenticationEncoder())
    ```
:::

然后你可以在连接建立阶段向接收方发送用户名和密码：

::: informalexample

Java

:   ``` java
    MimeType authenticationMimeType =
        MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString());
    UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
    Mono<RSocketRequester> requester = RSocketRequester.builder()
        .setupMetadata(credentials, authenticationMimeType)
        .rsocketStrategies(strategies.build())
        .connectTcp(host, port);
    ```

Kotlin

:   ``` kotlin
    val authenticationMimeType: MimeType =
        MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.string)
    val credentials = UsernamePasswordMetadata("user", "password")
    val requester: Mono<RSocketRequester> = RSocketRequester.builder()
        .setupMetadata(credentials, authenticationMimeType)
        .rsocketStrategies(strategies.build())
        .connectTcp(host, port)
    ```
:::

此外，也可以在请求中单独或额外发送用户名和密码：

::: informalexample

Java

:   ``` java
    Mono<RSocketRequester> requester;
    UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");

    public Mono<AirportLocation> findRadar(String code) {
        return this.requester.flatMap(req ->
            req.route("find.radar.{code}", code)
                .metadata(credentials, authenticationMimeType)
                .retrieveMono(AirportLocation.class)
        );
    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.messaging.rsocket.retrieveMono

    // ...

    var requester: Mono<RSocketRequester>? = null
    var credentials = UsernamePasswordMetadata("user", "password")

    open fun findRadar(code: String): Mono<AirportLocation> {
        return requester!!.flatMap { req ->
            req.route("find.radar.{code}", code)
                .metadata(credentials, authenticationMimeType)
                .retrieveMono<AirportLocation>()
        }
    }
    ```
:::

## JWT 认证 {#rsocket-authentication-jwt}

Spring Security 支持 [Bearer Token Authentication Metadata
Extension](https://github.com/rsocket/rsocket/blob/5920ed374d008abb712cb1fd7c9d91778b2f4a68/Extensions/Security/Bearer.md)。该支持包括对
JWT 的认证（验证 JWT 是否有效）以及使用 JWT 进行授权决策。

RSocket 接收方可通过 `BearerPayloadExchangeConverter`
解码凭证，该转换器会由 DSL 中的 `jwt`
部分自动配置。以下示例展示了一个典型配置：

::: informalexample

Java

:   ``` java
    @Bean
    PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
        rsocket
            .authorizePayload(authorize ->
                authorize
                    .anyRequest().authenticated()
                    .anyExchange().permitAll()
            )
            .jwt(Customizer.withDefaults());
        return rsocket.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun rsocketInterceptor(rsocket: RSocketSecurity): PayloadSocketAcceptorInterceptor {
        rsocket
            .authorizePayload { authorize -> authorize
                .anyRequest().authenticated()
                .anyExchange().permitAll()
            }
            .jwt(withDefaults())
        return rsocket.build()
    }
    ```
:::

上述配置依赖于存在一个 `ReactiveJwtDecoder` 类型的
`@Bean`。以下是如何从签发者（issuer）位置创建它的示例：

::: informalexample

Java

:   ``` java
    @Bean
    ReactiveJwtDecoder jwtDecoder() {
        return ReactiveJwtDecoders
            .fromIssuerLocation("https://example.com/auth/realms/demo");
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun jwtDecoder(): ReactiveJwtDecoder {
        return ReactiveJwtDecoders
            .fromIssuerLocation("https://example.com/auth/realms/demo")
    }
    ```
:::

RSocket 发送方无需特殊处理即可发送令牌，因为其值只是一个简单的
`String`。以下示例展示了如何在连接建立时发送令牌：

::: informalexample

Java

:   ``` java
    MimeType authenticationMimeType =
        MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString());
    BearerTokenMetadata token = ...;
    Mono<RSocketRequester> requester = RSocketRequester.builder()
        .setupMetadata(token, authenticationMimeType)
        .connectTcp(host, port);
    ```

Kotlin

:   ``` kotlin
    val authenticationMimeType: MimeType =
        MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.string)
    val token: BearerTokenMetadata = ...

    val requester = RSocketRequester.builder()
        .setupMetadata(token, authenticationMimeType)
        .connectTcp(host, port)
    ```
:::

此外，也可以在请求中发送令牌：

::: informalexample

Java

:   ``` java
    MimeType authenticationMimeType =
        MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString());
    Mono<RSocketRequester> requester;
    BearerTokenMetadata token = ...;

    public Mono<AirportLocation> findRadar(String code) {
        return this.requester.flatMap(req ->
            req.route("find.radar.{code}", code)
                .metadata(token, authenticationMimeType)
                .retrieveMono(AirportLocation.class)
        );
    }
    ```

Kotlin

:   ``` kotlin
    val authenticationMimeType: MimeType =
        MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.string)
    var requester: Mono<RSocketRequester>? = null
    val token: BearerTokenMetadata = ...

    open fun findRadar(code: String): Mono<AirportLocation> {
        return this.requester!!.flatMap { req ->
            req.route("find.radar.{code}", code)
                .metadata(token, authenticationMimeType)
                .retrieveMono<AirportLocation>()
        }
    }
    ```
:::

# RSocket 授权 {#rsocket-authorization}

RSocket 授权通过 `AuthorizationPayloadInterceptor`
执行，它作为控制器调用 `ReactiveAuthorizationManager` 实例。你可以使用
DSL 根据 `PayloadExchange` 设置授权规则。以下示例展示了一个配置：

::: informalexample

Java

:   ``` java
    rsocket
        .authorizePayload(authz ->
            authz
                .setup().hasRole("SETUP") 
                .route("fetch.profile.me").authenticated() 
                .matcher(payloadExchange -> isMatch(payloadExchange)) 
                    .hasRole("CUSTOM")
                .route("fetch.profile.{username}") 
                    .access((authentication, context) -> checkFriends(authentication, context))
                .anyRequest().authenticated() 
                .anyExchange().permitAll() 
        );
    ```

Kotlin

:   ``` kotlin
    rsocket
        .authorizePayload { authz ->
            authz
                .setup().hasRole("SETUP") 
                .route("fetch.profile.me").authenticated() 
                .matcher { payloadExchange -> isMatch(payloadExchange) } 
                .hasRole("CUSTOM")
                .route("fetch.profile.{username}") 
                .access { authentication, context -> checkFriends(authentication, context) }
                .anyRequest().authenticated() 
                .anyExchange().permitAll()
        } 
    ```
:::

- 建立连接需要具备 `ROLE_SETUP` 权限。

- 如果路由为 `fetch.profile.me`，授权只需用户通过身份验证即可。

- 此规则使用自定义匹配器，要求用户具备 `ROLE_CUSTOM` 权限。

- 此规则使用自定义授权逻辑。匹配器提取名为 `username`
  的变量并放入上下文（context）中，`checkFriends`
  方法实现具体的授权判断。

- 此规则确保未明确配置授权规则的请求仍需用户通过身份验证。\"请求\"指包含元数据的消息，不包括后续的数据负载。

- 此规则允许未配置任何授权规则的交换操作对所有人开放。在此示例中，意味着没有元数据的负载消息不受任何授权限制。

注意：授权规则按顺序执行，只有第一个匹配的规则会被执行。
