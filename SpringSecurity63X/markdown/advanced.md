`HttpSecurity.oauth2Login()` 提供了多种配置选项，用于自定义 OAuth 2.0
登录。主要的配置选项被分组到其对应的协议端点中。

例如，`oauth2Login().authorizationEndpoint()` 允许配置 *授权端点*，而
`oauth2Login().tokenEndpoint()` 允许配置 *令牌端点*。

以下代码展示了示例：

:::: example
::: title
高级 OAuth2 登录配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .authorizationEndpoint(authorization -> authorization
                            ...
                    )
                    .redirectionEndpoint(redirection -> redirection
                            ...
                    )
                    .tokenEndpoint(token -> token
                            ...
                    )
                    .userInfoEndpoint(userInfo -> userInfo
                            ...
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
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        ...
                    }
                    redirectionEndpoint {
                        ...
                    }
                    tokenEndpoint {
                        ...
                    }
                    userInfoEndpoint {
                        ...
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

`oauth2Login()` DSL 的主要目标是与规范中定义的命名保持高度一致。

OAuth 2.0 授权框架将
[协议端点](https://tools.ietf.org/html/rfc6749#section-3) 定义如下：

授权过程使用两个授权服务器端点（HTTP 资源）：

- 授权端点：客户端通过用户代理重定向方式从资源所有者获取授权。

- 令牌端点：客户端通过此端点交换授权凭证以获取访问令牌，通常需要客户端身份验证。

此外，授权过程还使用一个客户端端点：

- 重定向端点：授权服务器通过资源所有者的用户代理向客户端返回包含授权凭据的响应。

OpenID Connect Core 1.0 规范将 [UserInfo
端点](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
定义如下：

UserInfo 端点是一个受保护的 OAuth 2.0
资源，它返回有关已认证终端用户的声明。为了获得关于终端用户的请求声明，客户端需使用通过
OpenID Connect 认证获取的访问令牌向 UserInfo
端点发起请求。这些声明通常由一个 JSON
对象表示，该对象包含一组名称-值对的声明。

以下代码展示了 `oauth2Login()` DSL 可用的完整配置选项：

:::: example
::: title
OAuth2 登录配置选项
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .clientRegistrationRepository(this.clientRegistrationRepository())
                    .authorizedClientRepository(this.authorizedClientRepository())
                    .authorizedClientService(this.authorizedClientService())
                    .loginPage("/login")
                    .authorizationEndpoint(authorization -> authorization
                        .baseUri(this.authorizationRequestBaseUri())
                        .authorizationRequestRepository(this.authorizationRequestRepository())
                        .authorizationRequestResolver(this.authorizationRequestResolver())
                    )
                    .redirectionEndpoint(redirection -> redirection
                        .baseUri(this.authorizationResponseBaseUri())
                    )
                    .tokenEndpoint(token -> token
                        .accessTokenResponseClient(this.accessTokenResponseClient())
                    )
                    .userInfoEndpoint(userInfo -> userInfo
                        .userAuthoritiesMapper(this.userAuthoritiesMapper())
                        .userService(this.oauth2UserService())
                        .oidcUserService(this.oidcUserService())
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
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    clientRegistrationRepository = clientRegistrationRepository()
                    authorizedClientRepository = authorizedClientRepository()
                    authorizedClientService = authorizedClientService()
                    loginPage = "/login"
                    authorizationEndpoint {
                        baseUri = authorizationRequestBaseUri()
                        authorizationRequestRepository = authorizationRequestRepository()
                        authorizationRequestResolver = authorizationRequestResolver()
                    }
                    redirectionEndpoint {
                        baseUri = authorizationResponseBaseUri()
                    }
                    tokenEndpoint {
                        accessTokenResponseClient = accessTokenResponseClient()
                    }
                    userInfoEndpoint {
                        userAuthoritiesMapper = userAuthoritiesMapper()
                        userService = oauth2UserService()
                        oidcUserService = oidcUserService()
                    }
                }
            }
            return http.build()
        }
    }
    ```
::::

除了 `oauth2Login()` DSL 外，还支持 XML 配置。

以下代码展示了
[安全命名空间](servlet/appendix/namespace/http.xml#nsa-oauth2-login)
中可用的完整配置选项：

:::: formalpara
::: title
OAuth2 登录 XML 配置选项
:::

``` xml
<http>
    <oauth2-login client-registration-repository-ref="clientRegistrationRepository"
                  authorized-client-repository-ref="authorizedClientRepository"
                  authorized-client-service-ref="authorizedClientService"
                  authorization-request-repository-ref="authorizationRequestRepository"
                  authorization-request-resolver-ref="authorizationRequestResolver"
                  access-token-response-client-ref="accessTokenResponseClient"
                  user-authorities-mapper-ref="userAuthoritiesMapper"
                  user-service-ref="oauth2UserService"
                  oidc-user-service-ref="oidcUserService"
                  login-processing-url="/login/oauth2/code/*"
                  login-page="/login"
                  authentication-success-handler-ref="authenticationSuccessHandler"
                  authentication-failure-handler-ref="authenticationFailureHandler"
                  jwt-decoder-factory-ref="jwtDecoderFactory"/>
</http>
```
::::

接下来的部分将详细介绍每个可用的配置选项：

- [OAuth 2.0 登录页面](#oauth2login-advanced-login-page)

- [重定向端点](#oauth2login-advanced-redirection-endpoint)

- [UserInfo 端点](#oauth2login-advanced-userinfo-endpoint)

- [ID Token 签名验证](#oauth2login-advanced-idtoken-verify)

- [simpara_title](#oauth2login-advanced-oidc-logout)

# OAuth 2.0 登录页面 {#oauth2login-advanced-login-page}

默认情况下，OAuth 2.0 登录页面由 `DefaultLoginPageGeneratingFilter`
自动生成。默认登录页面显示每个配置的 OAuth 客户端，以其
`ClientRegistration.clientName` 作为链接，能够启动授权请求（或 OAuth 2.0
登录）。

:::: note
::: title
:::

为了让 `DefaultLoginPageGeneratingFilter` 显示配置的 OAuth
客户端链接，注册的 `ClientRegistrationRepository` 必须实现
`Iterable<ClientRegistration>` 接口。 可参考
`InMemoryClientRegistrationRepository`。
::::

每个 OAuth 客户端链接的目标地址默认为以下路径：

`OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{registrationId}"`

以下行展示了一个示例：

``` html
<a href="/oauth2/authorization/google">Google</a>
```

要覆盖默认登录页面，请配置 `oauth2Login().loginPage()`
和（可选）`oauth2Login().authorizationEndpoint().baseUri()`。

以下列表展示了示例：

:::: example
::: title
OAuth2 登录页面配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .loginPage("/login/oauth2")
                    ...
                    .authorizationEndpoint(authorization -> authorization
                        .baseUri("/login/oauth2/authorization")
                        ...
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
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    loginPage = "/login/oauth2"
                    authorizationEndpoint {
                        baseUri = "/login/oauth2/authorization"
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
        <oauth2-login login-page="/login/oauth2"
                      ...
        />
    </http>
    ```
::::

:::: important
::: title
:::

你需要提供一个带有 `@RequestMapping("/login/oauth2")` 的 `@Controller`
来渲染自定义登录页面。
::::

:::: tip
::: title
:::

如前所述，配置 `oauth2Login().authorizationEndpoint().baseUri()`
是可选的。但如果你选择自定义它，请确保每个 OAuth 客户端的链接与
`authorizationEndpoint().baseUri()` 匹配。

以下行展示了示例：

``` html
<a href="/login/oauth2/authorization/google">Google</a>
```
::::

# 重定向端点 {#oauth2login-advanced-redirection-endpoint}

重定向端点由授权服务器用于通过资源所有者的用户代理将授权响应（包含授权凭据）返回给客户端。

:::: tip
::: title
:::

OAuth 2.0 登录利用的是授权码授权模式。因此，授权凭据就是授权码。
::::

默认的授权响应 `baseUri`（即重定向端点）是 `/login/oauth2/code/*`，这在
`OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI` 中定义。

如果你想自定义授权响应的 `baseUri`，请按如下方式进行配置：

:::: example
::: title
重定向端点配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .redirectionEndpoint(redirection -> redirection
                        .baseUri("/login/oauth2/callback/*")
                        ...
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
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    redirectionEndpoint {
                        baseUri = "/login/oauth2/callback/*"
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
        <oauth2-login login-processing-url="/login/oauth2/callback/*"
                      ...
        />
    </http>
    ```
::::

::::: important
::: title
:::

你还必须确保 `ClientRegistration.redirectUri` 与自定义的授权响应
`baseUri` 相匹配。

以下列表展示了示例：

::: informalexample

Java

:   ``` java
    return CommonOAuth2Provider.GOOGLE.getBuilder("google")
        .clientId("google-client-id")
        .clientSecret("google-client-secret")
        .redirectUri("{baseUrl}/login/oauth2/callback/{registrationId}")
        .build();
    ```

Kotlin

:   ``` kotlin
    return CommonOAuth2Provider.GOOGLE.getBuilder("google")
        .clientId("google-client-id")
        .clientSecret("google-client-secret")
        .redirectUri("{baseUrl}/login/oauth2/callback/{registrationId}")
        .build()
    ```
:::
:::::

# UserInfo 端点 {#oauth2login-advanced-userinfo-endpoint}

UserInfo 端点包含多个配置选项，具体如下小节所述：

- [映射用户权限](#oauth2login-advanced-map-authorities)

- [OAuth 2.0 UserService](#oauth2login-advanced-oauth2-user-service)

- [OpenID Connect 1.0
  UserService](#oauth2login-advanced-oidc-user-service)

## 映射用户权限 {#oauth2login-advanced-map-authorities}

当用户成功通过 OAuth 2.0 提供商认证后，`OAuth2User.getAuthorities()`（或
`OidcUser.getAuthorities()`）会包含一个权限列表，这些权限来自
`OAuth2UserRequest.getAccessToken().getScopes()` 并以前缀 `SCOPE_`
添加。这些授予的权限可以映射为一组新的 `GrantedAuthority`
实例，并在完成认证时提供给 `OAuth2AuthenticationToken`。

:::: tip
::: title
:::

`OAuth2AuthenticationToken.getAuthorities()` 用于授权请求，比如
`hasRole('USER')` 或 `hasRole('ADMIN')`。
::::

在映射用户权限时，有几种可选方案：

- [使用
  GrantedAuthoritiesMapper](#oauth2login-advanced-map-authorities-grantedauthoritiesmapper)

- [基于委托策略的
  OAuth2UserService](#oauth2login-advanced-map-authorities-oauth2userservice)

### 使用 GrantedAuthoritiesMapper {#oauth2login-advanced-map-authorities-grantedauthoritiesmapper}

`GrantedAuthoritiesMapper` 接收一个权限列表，其中包含一种特殊类型的权限
`OAuth2UserAuthority` 和权限字符串 `OAUTH2_USER`（或 `OidcUserAuthority`
和 `OIDC_USER`）。

提供 `GrantedAuthoritiesMapper` 的实现并进行如下配置：

:::: example
::: title
Granted Authorities Mapper 配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .userInfoEndpoint(userInfo -> userInfo
                        .userAuthoritiesMapper(this.userAuthoritiesMapper())
                        ...
                    )
                );
            return http.build();
        }

        private GrantedAuthoritiesMapper userAuthoritiesMapper() {
            return (authorities) -> {
                Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                authorities.forEach(authority -> {
                    if (OidcUserAuthority.class.isInstance(authority)) {
                        OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;

                        OidcIdToken idToken = oidcUserAuthority.getIdToken();
                        OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                        // 将 idToken 和/或 userInfo 中的声明
                        // 映射为一个或多个 GrantedAuthority 并添加到 mappedAuthorities

                    } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                        OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;

                        Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                        // 将 userAttributes 中的属性
                        // 映射为一个或多个 GrantedAuthority 并添加到 mappedAuthorities

                    }
                });

                return mappedAuthorities;
            };
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    userInfoEndpoint {
                        userAuthoritiesMapper = userAuthoritiesMapper()
                    }
                }
            }
            return http.build()
        }

        private fun userAuthoritiesMapper(): GrantedAuthoritiesMapper = GrantedAuthoritiesMapper { authorities: Collection<GrantedAuthority> ->
            val mappedAuthorities = emptySet<GrantedAuthority>()

            authorities.forEach { authority ->
                if (authority is OidcUserAuthority) {
                    val idToken = authority.idToken
                    val userInfo = authority.userInfo
                    // 将 idToken 和/或 userInfo 中的声明
                    // 映射为一个或多个 GrantedAuthority 并添加到 mappedAuthorities
                } else if (authority is OAuth2UserAuthority) {
                    val userAttributes = authority.attributes
                    // 将 userAttributes 中的属性
                    // 映射为一个或多个 GrantedAuthority 并添加到 mappedAuthorities
                }
            }

            mappedAuthorities
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <oauth2-login user-authorities-mapper-ref="userAuthoritiesMapper"
                      ...
        />
    </http>
    ```
::::

或者，你可以注册一个 `GrantedAuthoritiesMapper`
`@Bean`，使其自动应用于配置中，如下所示：

:::: example
::: title
Granted Authorities Mapper Bean 配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(withDefaults());
            return http.build();
        }

        @Bean
        public GrantedAuthoritiesMapper userAuthoritiesMapper() {
            ...
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login { }
            }
            return http.build()
        }

        @Bean
        fun userAuthoritiesMapper(): GrantedAuthoritiesMapper {
            ...
        }
    }
    ```
::::

### 基于委托策略的 OAuth2UserService {#oauth2login-advanced-map-authorities-oauth2userservice}

这种策略比使用 `GrantedAuthoritiesMapper`
更高级，但也更灵活，因为它让你可以访问 `OAuth2UserRequest` 和
`OAuth2User`（使用 OAuth 2.0 UserService 时）或 `OidcUserRequest` 和
`OidcUser`（使用 OpenID Connect 1.0 UserService 时）。

`OAuth2UserRequest`（和 `OidcUserRequest`）让你可以访问相关的
`OAuth2AccessToken`，这对于需要使用访问令牌从受保护资源获取权限信息后再映射用户自定义权限的"委托方"非常有用。

以下示例展示了如何实现并配置基于委托策略的 OpenID Connect 1.0
UserService：

:::: example
::: title
OAuth2UserService 配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .userInfoEndpoint(userInfo -> userInfo
                        .oidcUserService(this.oidcUserService())
                        ...
                    )
                );
            return http.build();
        }

        private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
            final OidcUserService delegate = new OidcUserService();

            return (userRequest) -> {
                // 委托默认实现加载用户
                OidcUser oidcUser = delegate.loadUser(userRequest);

                OAuth2AccessToken accessToken = userRequest.getAccessToken();
                Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                // TODO
                // 1) 使用 accessToken 从受保护资源获取权限信息
                // 2) 将权限信息映射为一个或多个 GrantedAuthority 并添加到 mappedAuthorities

                // 3) 创建 oidcUser 的副本，但使用 mappedAuthorities 替代原权限
                ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
                String userNameAttributeName = providerDetails.getUserInfoEndpoint().getUserNameAttributeName();
                if (StringUtils.hasText(userNameAttributeName)) {
                    oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo(), userNameAttributeName);
                } else {
                    oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
                }

                return oidcUser;
            };
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class OAuth2LoginSecurityConfig  {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    userInfoEndpoint {
                        oidcUserService = oidcUserService()
                    }
                }
            }
            return http.build()
        }

        @Bean
        fun oidcUserService(): OAuth2UserService<OidcUserRequest, OidcUser> {
            val delegate = OidcUserService()

            return OAuth2UserService { userRequest ->
                // 委托默认实现加载用户
                val oidcUser = delegate.loadUser(userRequest)

                val accessToken = userRequest.accessToken
                val mappedAuthorities = HashSet<GrantedAuthority>()

                // TODO
                // 1) 使用 accessToken 从受保护资源获取权限信息
                // 2) 将权限信息映射为一个或多个 GrantedAuthority 并添加到 mappedAuthorities
                // 3) 创建 oidcUser 的副本，但使用 mappedAuthorities 替代原权限
                val providerDetails = userRequest.getClientRegistration().getProviderDetails()
                val userNameAttributeName = providerDetails.getUserInfoEndpoint().getUserNameAttributeName()
                if (StringUtils.hasText(userNameAttributeName)) {
                    DefaultOidcUser(mappedAuthorities, oidcUser.idToken, oidcUser.userInfo, userNameAttributeName)
                } else {
                    DefaultOidcUser(mappedAuthorities, oidcUser.idToken, oidcUser.userInfo)
                }
            }
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <oauth2-login oidc-user-service-ref="oidcUserService"
                      ...
        />
    </http>
    ```
::::

## OAuth 2.0 UserService {#oauth2login-advanced-oauth2-user-service}

`DefaultOAuth2UserService` 是 `OAuth2UserService` 的一个实现，支持标准的
OAuth 2.0 提供商。

:::: note
::: title
:::

`OAuth2UserService` 使用授权流程期间授予客户端的访问令牌，从 UserInfo
端点获取最终用户（资源所有者）的用户属性，并以 `OAuth2User` 形式返回一个
`AuthenticatedPrincipal`。
::::

`DefaultOAuth2UserService` 在请求 UserInfo 端点的用户属性时使用
`RestOperations` 实例。

如果需要自定义 UserInfo 请求的预处理，可以通过
`DefaultOAuth2UserService.setRequestEntityConverter()` 提供自定义的
`Converter<OAuth2UserRequest, RequestEntity<?>>`。默认实现
`OAuth2UserRequestEntityConverter` 构建了一个 UserInfo 请求的
`RequestEntity` 表示，默认将 `OAuth2AccessToken` 设置在 `Authorization`
请求头中。

另一方面，如果需要自定义 UserInfo 响应的后处理，则需要通过
`DefaultOAuth2UserService.setRestOperations()` 提供自定义配置的
`RestOperations`。默认的 `RestOperations` 配置如下：

``` java
RestTemplate restTemplate = new RestTemplate();
restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

`OAuth2ErrorResponseErrorHandler` 是一个
`ResponseErrorHandler`，可以处理 OAuth 2.0 错误（400 Bad
Request）。它使用 `OAuth2ErrorHttpMessageConverter` 将 OAuth 2.0
错误参数转换为 `OAuth2Error`。

无论你是自定义 `DefaultOAuth2UserService` 还是提供自己的
`OAuth2UserService` 实现，都需要如下配置：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .userInfoEndpoint(userInfo -> userInfo
                        .userService(this.oauth2UserService())
                        ...
                    )
                );
            return http.build();
        }

        private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
            ...
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    userInfoEndpoint {
                        userService = oauth2UserService()
                        // ...
                    }
                }
            }
            return http.build()
        }

        private fun oauth2UserService(): OAuth2UserService<OAuth2UserRequest, OAuth2User> {
            // ...
        }
    }
    ```
:::

## OpenID Connect 1.0 UserService {#oauth2login-advanced-oidc-user-service}

`OidcUserService` 是 `OAuth2UserService` 的一个实现，支持 OpenID Connect
1.0 提供商。

`OidcUserService` 在请求 UserInfo 端点的用户属性时会借助
`DefaultOAuth2UserService`。

如果需要自定义 UserInfo 请求的预处理或 UserInfo 响应的后处理，需通过
`OidcUserService.setOauth2UserService()` 提供自定义配置的
`DefaultOAuth2UserService`。

无论是自定义 `OidcUserService` 还是为 OpenID Connect 1.0
提供商提供自己的 `OAuth2UserService` 实现，都需要如下配置：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .oauth2Login(oauth2 -> oauth2
                    .userInfoEndpoint(userInfo -> userInfo
                        .oidcUserService(this.oidcUserService())
                        ...
                    )
                );
            return http.build();
        }

        private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
            ...
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class OAuth2LoginSecurityConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    userInfoEndpoint {
                        oidcUserService = oidcUserService()
                        // ...
                    }
                }
            }
            return http.build()
        }

        private fun oidcUserService(): OAuth2UserService<OidcUserRequest, OidcUser> {
            // ...
        }
    }
    ```
:::

# ID Token 签名验证 {#oauth2login-advanced-idtoken-verify}

OpenID Connect 1.0 认证引入了 [ID
Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)，这是一个安全令牌，包含授权服务器对终端用户进行认证的声明，供客户端使用。

ID Token 以 [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT)
格式表示，并且必须使用 [JSON Web
Signature](https://tools.ietf.org/html/rfc7515) (JWS) 进行签名。

`OidcIdTokenDecoderFactory` 提供了一个用于 `OidcIdToken` 签名验证的
`JwtDecoder`。默认算法为
`RS256`，但在客户端注册期间可能分配不同的算法。在这种情况下，你可以配置一个解析器来返回特定客户端预期的
JWS 算法。

JWS 算法解析器是一个 `Function`，接受一个 `ClientRegistration`
并返回客户端预期的 `JwsAlgorithm`，例如 `SignatureAlgorithm.RS256` 或
`MacAlgorithm.HS256`。

以下代码展示了如何配置 `OidcIdTokenDecoderFactory` `@Bean`，使所有
`ClientRegistration` 实例默认使用 `MacAlgorithm.HS256`：

::: informalexample

Java

:   ``` java
    @Bean
    public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
        OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
        idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> MacAlgorithm.HS256);
        return idTokenDecoderFactory;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun idTokenDecoderFactory(): JwtDecoderFactory<ClientRegistration?> {
        val idTokenDecoderFactory = OidcIdTokenDecoderFactory()
        idTokenDecoderFactory.setJwsAlgorithmResolver { MacAlgorithm.HS256 }
        return idTokenDecoderFactory
    }
    ```
:::

:::: note
::: title
:::

对于基于 MAC 的算法（如 `HS256`、`HS384` 或 `HS512`），对应 `client-id`
的 `client-secret` 将作为对称密钥用于签名验证。
::::

:::: tip
::: title
:::

如果为 OpenID Connect 1.0 认证配置了多个 `ClientRegistration`，JWS
算法解析器可能会评估提供的 `ClientRegistration` 以确定应返回哪个算法。
::::

然后，你可以继续配置 [登出](servlet/oauth2/login/logout.xml)
