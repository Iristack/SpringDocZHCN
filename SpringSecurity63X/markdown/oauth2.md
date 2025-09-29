在处理 OAuth 2.0 时，之前提到的原则仍然适用：最终取决于被测方法期望
`SecurityContextHolder` 中包含什么内容。

例如，对于如下所示的控制器：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(Principal user) {
        return user.getName();
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(user: Principal): String {
        return user.name
    }
    ```
:::

这个控制器与 OAuth 2.0 没有特定关联，因此你可能只需使用
[`@WithMockUser`](servlet/test/method.xml#test-method-withmockuser)
就可以满足测试需求。

但是，如果控制器依赖于 Spring Security 的 OAuth 2.0
支持的某些特性，比如以下这种情况：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(@AuthenticationPrincipal OidcUser user) {
        return user.getIdToken().getSubject();
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(@AuthenticationPrincipal user: OidcUser): String {
        return user.idToken.subject
    }
    ```
:::

那么 Spring Security 提供的测试支持将会非常有用。

# 测试 OIDC 登录 {#testing-oidc-login}

使用 Spring MVC Test
对上述方法进行测试需要模拟某种授权服务器的授权流程。这无疑是一项艰巨的任务，因此
Spring Security 提供了相应的支持以减少这些样板代码。

例如，我们可以告诉 Spring Security 使用 `oidcLogin`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)
来包含一个默认的 `OidcUser`，如下所示：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint").with(oidcLogin()));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(oidcLogin())
    }
    ```
:::

这样做的效果是为关联的 `MockHttpServletRequest` 配置一个
`OidcUser`，该用户包含一个简单的 `OidcIdToken`、`OidcUserInfo`
和一组授予的权限（granted authorities）。

具体来说，它会包含一个 `sub` 声明值为 `user` 的 `OidcIdToken`：

::: informalexample

Java

:   ``` java
    assertThat(user.getIdToken().getClaim("sub")).isEqualTo("user");
    ```

Kotlin

:   ``` kotlin
    assertThat(user.idToken.getClaim<String>("sub")).isEqualTo("user")
    ```
:::

一个没有任何声明的 `OidcUserInfo`：

::: informalexample

Java

:   ``` java
    assertThat(user.getUserInfo().getClaims()).isEmpty();
    ```

Kotlin

:   ``` kotlin
    assertThat(user.userInfo.claims).isEmpty()
    ```
:::

以及仅包含一个权限 `SCOPE_read` 的权限集合：

::: informalexample

Java

:   ``` java
    assertThat(user.getAuthorities()).hasSize(1);
    assertThat(user.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_read"));
    ```

Kotlin

:   ``` kotlin
    assertThat(user.authorities).hasSize(1)
    assertThat(user.authorities).containsExactly(SimpleGrantedAuthority("SCOPE_read"))
    ```
:::

Spring Security 会完成必要的工作，确保 `OidcUser` 实例可用于
[`@AuthenticationPrincipal`
注解](servlet/integrations/mvc.xml#mvc-authentication-principal)。

此外，它还会将该 `OidcUser` 与一个简单的 `OAuth2AuthorizedClient`
实例关联，并将其存入一个模拟的
`OAuth2AuthorizedClientRepository`。如果你的测试 [使用了
`@RegisteredOAuth2AuthorizedClient`
注解](#testing-oauth2-client)，这将非常有用。

# 配置权限 {#testing-oidc-login-authorities}

在许多情况下，你的方法受到过滤器或方法安全性的保护，需要
`Authentication` 具备特定的授予权限才能允许请求通过。

在这种情况下，你可以使用 `authorities()` 方法提供所需的权限：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(oidcLogin()
                .authorities(new SimpleGrantedAuthority("SCOPE_message:read"))
            )
        );
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(oidcLogin()
            .authorities(SimpleGrantedAuthority("SCOPE_message:read"))
        )
    }
    ```
:::

# 配置声明 {#testing-oidc-login-claims}

虽然授予的权限在 Spring Security 中很常见，但在 OAuth 2.0
中我们也有声明（claims）的概念。

假设，例如，你有一个 `user_id` 声明用于表示系统中的用户
ID。你可能会在控制器中这样访问它：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(@AuthenticationPrincipal OidcUser oidcUser) {
        String userId = oidcUser.getIdToken().getClaim("user_id");
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(@AuthenticationPrincipal oidcUser: OidcUser): String {
        val userId = oidcUser.idToken.getClaim<String>("user_id")
        // ...
    }
    ```
:::

在这种情况下，你需要使用 `idToken()` 方法来指定该声明：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(oidcLogin()
                    .idToken(token -> token.claim("user_id", "1234"))
            )
        );
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(oidcLogin()
            .idToken {
                it.claim("user_id", "1234")
            }
        )
    }
    ```
:::

因为 `OidcUser` 是从 `OidcIdToken` 获取其声明的。

# 其他配置 {#testing-oidc-login-user}

还有其他一些方法可以进一步配置身份验证；这完全取决于你的控制器期望的数据：

- `userInfo(OidcUserInfo.Builder)` - 用于配置 `OidcUserInfo` 实例

- `clientRegistration(ClientRegistration)` - 用于使用给定的
  `ClientRegistration` 配置关联的 `OAuth2AuthorizedClient`

- `oidcUser(OidcUser)` - 用于配置完整的 `OidcUser` 实例

最后一个方法在以下情况中很有用： 1. 你有自己的 `OidcUser` 实现，或者 2.
需要更改名称属性

例如，假设你的授权服务器将主体名称放在 `user_name` 声明中而不是 `sub`
声明中。在这种情况下，你可以手动配置一个 `OidcUser`：

::: informalexample

Java

:   ``` java
    OidcUser oidcUser = new DefaultOidcUser(
            AuthorityUtils.createAuthorityList("SCOPE_message:read"),
            OidcIdToken.withTokenValue("id-token").claim("user_name", "foo_user").build(),
            "user_name");

    mvc
        .perform(get("/endpoint")
            .with(oidcLogin().oidcUser(oidcUser))
        );
    ```

Kotlin

:   ``` kotlin
    val oidcUser: OidcUser = DefaultOidcUser(
        AuthorityUtils.createAuthorityList("SCOPE_message:read"),
        OidcIdToken.withTokenValue("id-token").claim("user_name", "foo_user").build(),
        "user_name"
    )

    mvc.get("/endpoint") {
        with(oidcLogin().oidcUser(oidcUser))
    }
    ```
:::

# 测试 OAuth 2.0 登录 {#testing-oauth2-login}

与 [测试 OIDC 登录](#testing-oidc-login) 类似，测试 OAuth 2.0
登录也面临模拟授权流程的挑战。因此，Spring Security 也为非 OIDC
场景提供了测试支持。

假设我们有一个控制器，它获取登录用户作为 `OAuth2User`：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(@AuthenticationPrincipal OAuth2User oauth2User) {
        return oauth2User.getAttribute("sub");
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(@AuthenticationPrincipal oauth2User: OAuth2User): String? {
        return oauth2User.getAttribute("sub")
    }
    ```
:::

在这种情况下，我们可以告诉 Spring Security 使用 `oauth2Login`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)
包含一个默认的 `OAuth2User`，如下所示：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint").with(oauth2Login()));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(oauth2Login())
    }
    ```
:::

这样做的效果是为关联的 `MockHttpServletRequest` 配置一个
`OAuth2User`，其中包含一个简单的属性 `Map` 和授予权限的 `Collection`。

具体来说，它将包含一个键/值对为 `sub`/`user` 的 `Map`：

::: informalexample

Java

:   ``` java
    assertThat((String) user.getAttribute("sub")).isEqualTo("user");
    ```

Kotlin

:   ``` kotlin
    assertThat(user.getAttribute<String>("sub")).isEqualTo("user")
    ```
:::

以及一个仅包含一个权限 `SCOPE_read` 的权限集合：

::: informalexample

Java

:   ``` java
    assertThat(user.getAuthorities()).hasSize(1);
    assertThat(user.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_read"));
    ```

Kotlin

:   ``` kotlin
    assertThat(user.authorities).hasSize(1)
    assertThat(user.authorities).containsExactly(SimpleGrantedAuthority("SCOPE_read"))
    ```
:::

Spring Security 会完成必要的工作，确保 `OAuth2User` 实例可用于
[`@AuthenticationPrincipal`
注解](servlet/integrations/mvc.xml#mvc-authentication-principal)。

此外，它还会将该 `OAuth2User` 与一个简单的 `OAuth2AuthorizedClient`
实例关联，并将其存入一个模拟的
`OAuth2AuthorizedClientRepository`。如果你的测试 [使用了
`@RegisteredOAuth2AuthorizedClient`
注解](#testing-oauth2-client)，这将非常有用。

# 配置权限 {#testing-oauth2-login-authorities}

在许多情况下，你的方法受到过滤器或方法安全性的保护，需要
`Authentication` 具备特定的授予权限才能允许请求通过。

在这种情况下，你可以使用 `authorities()` 方法提供所需的权限：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(oauth2Login()
                .authorities(new SimpleGrantedAuthority("SCOPE_message:read"))
            )
        );
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(oauth2Login()
            .authorities(SimpleGrantedAuthority("SCOPE_message:read"))
        )
    }
    ```
:::

# 配置声明 {#testing-oauth2-login-claims}

虽然授予的权限在 Spring Security 中很常见，但在 OAuth 2.0
中我们也拥有声明。

假设，例如，你有一个 `user_id` 属性用于表示系统中的用户
ID。你可能会在控制器中这样访问它：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(@AuthenticationPrincipal OAuth2User oauth2User) {
        String userId = oauth2User.getAttribute("user_id");
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(@AuthenticationPrincipal oauth2User: OAuth2User): String {
        val userId = oauth2User.getAttribute<String>("user_id")
        // ...
    }
    ```
:::

在这种情况下，你应使用 `attributes()` 方法来指定该属性：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(oauth2Login()
                    .attributes(attrs -> attrs.put("user_id", "1234"))
            )
        );
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(oauth2Login()
            .attributes { attrs -> attrs["user_id"] = "1234" }
        )
    }
    ```
:::

# 其他配置 {#testing-oauth2-login-user}

还有一些额外的方法可用于进一步配置身份验证；这完全取决于你的控制器期望的数据：

- `clientRegistration(ClientRegistration)` - 用于使用给定的
  `ClientRegistration` 配置关联的 `OAuth2AuthorizedClient`

- `oauth2User(OAuth2User)` - 用于配置完整的 `OAuth2User` 实例

最后一个方法在以下情况中很有用： 1. 你有自己的 `OAuth2User` 实现，或者
2. 需要更改名称属性

例如，假设你的授权服务器将主体名称放在 `user_name` 声明中而不是 `sub`
声明中。在这种情况下，你可以手动配置一个 `OAuth2User`：

::: informalexample

Java

:   ``` java
    OAuth2User oauth2User = new DefaultOAuth2User(
            AuthorityUtils.createAuthorityList("SCOPE_message:read"),
            Collections.singletonMap("user_name", "foo_user"),
            "user_name");

    mvc
        .perform(get("/endpoint")
            .with(oauth2Login().oauth2User(oauth2User))
        );
    ```

Kotlin

:   ``` kotlin
    val oauth2User: OAuth2User = DefaultOAuth2User(
        AuthorityUtils.createAuthorityList("SCOPE_message:read"),
        mapOf(Pair("user_name", "foo_user")),
        "user_name"
    )

    mvc.get("/endpoint") {
        with(oauth2Login().oauth2User(oauth2User))
    }
    ```
:::

# 测试 OAuth 2.0 客户端 {#testing-oauth2-client}

无论用户如何认证，你的请求测试中可能还涉及其他令牌和客户端注册信息。例如，你的控制器可能依赖客户端凭据模式获取一个与用户无关的令牌：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(@RegisteredOAuth2AuthorizedClient("my-app") OAuth2AuthorizedClient authorizedClient) {
        return this.webClient.get()
            .attributes(oauth2AuthorizedClient(authorizedClient))
            .retrieve()
            .bodyToMono(String.class)
            .block();
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(@RegisteredOAuth2AuthorizedClient("my-app") authorizedClient: OAuth2AuthorizedClient?): String? {
        return this.webClient.get()
            .attributes(oauth2AuthorizedClient(authorizedClient))
            .retrieve()
            .bodyToMono(String::class.java)
            .block()
    }
    ```
:::

模拟与授权服务器的握手过程可能很繁琐。相反，你可以使用 `oauth2Client`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)
将 `OAuth2AuthorizedClient` 添加到一个模拟的
`OAuth2AuthorizedClientRepository` 中：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint").with(oauth2Client("my-app")));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(
            oauth2Client("my-app")
        )
    }
    ```
:::

这将创建一个包含简单 `ClientRegistration`、`OAuth2AccessToken`
和资源所有者名称的 `OAuth2AuthorizedClient`。

具体来说，它将包含一个客户端 ID 为 \"test-client\" 且客户端密钥为
\"test-secret\" 的 `ClientRegistration`：

::: informalexample

Java

:   ``` java
    assertThat(authorizedClient.getClientRegistration().getClientId()).isEqualTo("test-client");
    assertThat(authorizedClient.getClientRegistration().getClientSecret()).isEqualTo("test-secret");
    ```

Kotlin

:   ``` kotlin
    assertThat(authorizedClient.clientRegistration.clientId).isEqualTo("test-client")
    assertThat(authorizedClient.clientRegistration.clientSecret).isEqualTo("test-secret")
    ```
:::

资源所有者名称为 \"user\"：

::: informalexample

Java

:   ``` java
    assertThat(authorizedClient.getPrincipalName()).isEqualTo("user");
    ```

Kotlin

:   ``` kotlin
    assertThat(authorizedClient.principalName).isEqualTo("user")
    ```
:::

以及一个仅包含一个范围 `read` 的 `OAuth2AccessToken`：

::: informalexample

Java

:   ``` java
    assertThat(authorizedClient.getAccessToken().getScopes()).hasSize(1);
    assertThat(authorizedClient.getAccessToken().getScopes()).containsExactly("read");
    ```

Kotlin

:   ``` kotlin
    assertThat(authorizedClient.accessToken.scopes).hasSize(1)
    assertThat(authorizedClient.accessToken.scopes).containsExactly("read")
    ```
:::

然后，控制器方法可以通过 `@RegisteredOAuth2AuthorizedClient`
正常检索该客户端。

# 配置作用域 {#testing-oauth2-client-scopes}

在很多情况下，OAuth 2.0
访问令牌附带一组作用域（scopes）。如果你的控制器检查这些作用域，例如：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(@RegisteredOAuth2AuthorizedClient("my-app") OAuth2AuthorizedClient authorizedClient) {
        Set<String> scopes = authorizedClient.getAccessToken().getScopes();
        if (scopes.contains("message:read")) {
            return this.webClient.get()
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        }
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(@RegisteredOAuth2AuthorizedClient("my-app") authorizedClient: OAuth2AuthorizedClient): String? {
        val scopes = authorizedClient.accessToken.scopes
        if (scopes.contains("message:read")) {
            return webClient.get()
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String::class.java)
                .block()
        }
        // ...
    }
    ```
:::

那么你可以使用 `accessToken()` 方法来配置作用域：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(oauth2Client("my-app")
                .accessToken(new OAuth2AccessToken(BEARER, "token", null, null, Collections.singleton("message:read"))))
            )
        );
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(oauth2Client("my-app")
                .accessToken(OAuth2AccessToken(BEARER, "token", null, null, Collections.singleton("message:read")))
        )
    }
    ```
:::

# 其他配置 {#testing-oauth2-client-registration}

还有其他方法可用于进一步配置身份验证；这完全取决于你的控制器期望的数据：

- `principalName(String)` - 用于配置资源所有者名称

- `clientRegistration(Consumer<ClientRegistration.Builder>)` -
  用于配置关联的 `ClientRegistration`

- `clientRegistration(ClientRegistration)` - 用于配置完整的
  `ClientRegistration`

最后一个方法在你想使用真实 `ClientRegistration` 时很有用。

例如，假设你想使用你在 `application.yml` 中定义的应用程序的一个
`ClientRegistration`。

在这种情况下，你的测试可以自动装配 `ClientRegistrationRepository`
并查找测试所需的那个：

::: informalexample

Java

:   ``` java
    @Autowired
    ClientRegistrationRepository clientRegistrationRepository;

    // ...

    mvc
        .perform(get("/endpoint")
            .with(oauth2Client()
                .clientRegistration(this.clientRegistrationRepository.findByRegistrationId("facebook"))));
    ```

Kotlin

:   ``` kotlin
    @Autowired
    lateinit var clientRegistrationRepository: ClientRegistrationRepository

    // ...

    mvc.get("/endpoint") {
        with(oauth2Client("my-app")
            .clientRegistration(clientRegistrationRepository.findByRegistrationId("facebook"))
        )
    }
    ```
:::

# 测试 JWT 身份验证 {#testing-jwt}

为了在资源服务器上发出经过身份验证的请求，你需要一个承载令牌（bearer
token）。

如果你的资源服务器配置为使用 JWT，则意味着承载令牌必须根据 JWT
规范进行签名并编码。所有这些都可能相当复杂，尤其是当这不是你测试的重点时。

幸运的是，有几种简单的方法可以帮助你克服这一困难，让你的测试专注于授权而非承载令牌的表示形式。我们现在来看其中两种方法：

# `jwt()` RequestPostProcessor {#_jwt_requestpostprocessor}

第一种方式是通过 `jwt`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)。最简单的使用方式如下：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint").with(jwt()));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(jwt())
    }
    ```
:::

这将创建一个模拟的 `Jwt`，并正确地将其传递给任何身份验证
API，以便你的授权机制可以验证它。

默认情况下，创建的 `JWT` 具有以下特征：

``` json
{
  "headers" : { "alg" : "none" },
  "claims" : {
    "sub" : "user",
    "scope" : "read"
  }
}
```

如果对该 `Jwt` 进行测试，结果将是：

::: informalexample

Java

:   ``` java
    assertThat(jwt.getTokenValue()).isEqualTo("token");
    assertThat(jwt.getHeaders().get("alg")).isEqualTo("none");
    assertThat(jwt.getSubject()).isEqualTo("sub");
    ```

Kotlin

:   ``` kotlin
    assertThat(jwt.tokenValue).isEqualTo("token")
    assertThat(jwt.headers["alg"]).isEqualTo("none")
    assertThat(jwt.subject).isEqualTo("sub")
    ```
:::

当然，这些值是可以配置的。

任何头部或声明都可以通过对应的方法进行配置：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(jwt().jwt(jwt -> jwt.header("kid", "one").claim("iss", "https://idp.example.org"))));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(
            jwt().jwt { jwt -> jwt.header("kid", "one").claim("iss", "https://idp.example.org") }
        )
    }
    ```
:::

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(jwt().jwt(jwt -> jwt.claims(claims -> claims.remove("scope")))));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(
            jwt().jwt { jwt -> jwt.claims { claims -> claims.remove("scope") } }
        )
    }
    ```
:::

`scope` 和 `scp`
声明在此处的处理方式与正常承载令牌请求中的处理方式相同。然而，这可以通过直接提供测试所需的
`GrantedAuthority` 实例列表来覆盖：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_messages"))));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(
            jwt().authorities(SimpleGrantedAuthority("SCOPE_messages"))
        )
    }
    ```
:::

或者，如果你有一个自定义的 `Jwt` 到 `Collection<GrantedAuthority>`
的转换器，也可以使用它来派生权限：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(jwt().authorities(new MyConverter())));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(
            jwt().authorities(MyConverter())
        )
    }
    ```
:::

你还可以指定一个完整的 `Jwt`，此时
`{security-api-url}org/springframework/security/oauth2/jwt/Jwt.Builder.html[Jwt.Builder]`
会非常有用：

::: informalexample

Java

:   ``` java
    Jwt jwt = Jwt.withTokenValue("token")
        .header("alg", "none")
        .claim("sub", "user")
        .claim("scope", "read")
        .build();

    mvc
        .perform(get("/endpoint")
            .with(jwt().jwt(jwt)));
    ```

Kotlin

:   ``` kotlin
    val jwt: Jwt = Jwt.withTokenValue("token")
        .header("alg", "none")
        .claim("sub", "user")
        .claim("scope", "read")
        .build()

    mvc.get("/endpoint") {
        with(
            jwt().jwt(jwt)
        )
    }
    ```
:::

# `authentication()` `RequestPostProcessor` {#_authentication_requestpostprocessor}

第二种方式是使用 `authentication()`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)。本质上，你可以实例化自己的
`JwtAuthenticationToken` 并在测试中提供它，如下所示：

::: informalexample

Java

:   ``` java
    Jwt jwt = Jwt.withTokenValue("token")
        .header("alg", "none")
        .claim("sub", "user")
        .build();
    Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("SCOPE_read");
    JwtAuthenticationToken token = new JwtAuthenticationToken(jwt, authorities);

    mvc
        .perform(get("/endpoint")
            .with(authentication(token)));
    ```

Kotlin

:   ``` kotlin
    val jwt = Jwt.withTokenValue("token")
        .header("alg", "none")
        .claim("sub", "user")
        .build()
    val authorities: Collection<GrantedAuthority> = AuthorityUtils.createAuthorityList("SCOPE_read")
    val token = JwtAuthenticationToken(jwt, authorities)

    mvc.get("/endpoint") {
        with(
            authentication(token)
        )
    }
    ```
:::

请注意，除了这些方法之外，你还可以使用 `@MockBean` 注解来模拟
`JwtDecoder` Bean 本身。

# 测试不透明令牌身份验证 {#testing-opaque-token}

类似于
[JWT](#testing-jwt)，不透明令牌需要授权服务器来验证其有效性，这会使测试更加困难。为此，Spring
Security 提供了对不透明令牌的测试支持。

假设我们有一个控制器，它将身份验证作为 `BearerTokenAuthentication`
获取：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(BearerTokenAuthentication authentication) {
        return (String) authentication.getTokenAttributes().get("sub");
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(authentication: BearerTokenAuthentication): String {
        return authentication.tokenAttributes["sub"] as String
    }
    ```
:::

在这种情况下，我们可以告诉 Spring Security 使用 `opaqueToken`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)
方法包含一个默认的 `BearerTokenAuthentication`，如下所示：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint").with(opaqueToken()));
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(opaqueToken())
    }
    ```
:::

这将为关联的 `MockHttpServletRequest` 配置一个
`BearerTokenAuthentication`，其中包括一个简单的
`OAuth2AuthenticatedPrincipal`、属性 `Map` 和授予权限的 `Collection`。

具体来说，它将包含一个键/值对为 `sub`/`user` 的 `Map`：

::: informalexample

Java

:   ``` java
    assertThat((String) token.getTokenAttributes().get("sub")).isEqualTo("user");
    ```

Kotlin

:   ``` kotlin
    assertThat(token.tokenAttributes["sub"] as String).isEqualTo("user")
    ```
:::

以及一个仅包含一个权限 `SCOPE_read` 的权限集合：

::: informalexample

Java

:   ``` java
    assertThat(token.getAuthorities()).hasSize(1);
    assertThat(token.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_read"));
    ```

Kotlin

:   ``` kotlin
    assertThat(token.authorities).hasSize(1)
    assertThat(token.authorities).containsExactly(SimpleGrantedAuthority("SCOPE_read"))
    ```
:::

Spring Security 会完成必要的工作，确保 `BearerTokenAuthentication`
实例可用于你的控制器方法。

# 配置权限 {#testing-opaque-token-authorities}

在许多情况下，你的方法受到过滤器或方法安全性的保护，需要
`Authentication` 具备特定的授予权限才能允许请求通过。

在这种情况下，你可以使用 `authorities()` 方法提供所需的权限：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(opaqueToken()
                .authorities(new SimpleGrantedAuthority("SCOPE_message:read"))
            )
        );
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(opaqueToken()
            .authorities(SimpleGrantedAuthority("SCOPE_message:read"))
        )
    }
    ```
:::

# 配置声明 {#testing-opaque-token-attributes}

虽然授予的权限在 Spring Security 中很常见，但在 OAuth 2.0
中我们也拥有属性。

假设，例如，你有一个 `user_id` 属性用于表示系统中的用户
ID。你可能会在控制器中这样访问它：

::: informalexample

Java

:   ``` java
    @GetMapping("/endpoint")
    public String foo(BearerTokenAuthentication authentication) {
        String userId = (String) authentication.getTokenAttributes().get("user_id");
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @GetMapping("/endpoint")
    fun foo(authentication: BearerTokenAuthentication): String {
        val userId = authentication.tokenAttributes["user_id"] as String
        // ...
    }
    ```
:::

在这种情况下，你应该使用 `attributes()` 方法来指定该属性：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/endpoint")
            .with(opaqueToken()
                    .attributes(attrs -> attrs.put("user_id", "1234"))
            )
        );
    ```

Kotlin

:   ``` kotlin
    mvc.get("/endpoint") {
        with(opaqueToken()
            .attributes { attrs -> attrs["user_id"] = "1234" }
        )
    }
    ```
:::

# 其他配置 {#testing-opaque-token-principal}

还有其他方法可用于进一步配置身份验证；这完全取决于你的控制器期望的数据。

其中之一是 `principal(OAuth2AuthenticatedPrincipal)`，可用于配置底层
`BearerTokenAuthentication` 所依赖的完整 `OAuth2AuthenticatedPrincipal`
实例。

它在以下情况中很有用： 1. 你有自己的 `OAuth2AuthenticatedPrincipal`
实现，或者 2. 想要指定不同的主体名称

例如，假设你的授权服务器将主体名称放在 `user_name` 属性中而不是 `sub`
属性中。在这种情况下，你可以手动配置一个
`OAuth2AuthenticatedPrincipal`：

::: informalexample

Java

:   ``` java
    Map<String, Object> attributes = Collections.singletonMap("user_name", "foo_user");
    OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(
            (String) attributes.get("user_name"),
            attributes,
            AuthorityUtils.createAuthorityList("SCOPE_message:read"));

    mvc
        .perform(get("/endpoint")
            .with(opaqueToken().principal(principal))
        );
    ```

Kotlin

:   ``` kotlin
    val attributes: Map<String, Any> = Collections.singletonMap("user_name", "foo_user")
    val principal: OAuth2AuthenticatedPrincipal = DefaultOAuth2AuthenticatedPrincipal(
        attributes["user_name"] as String?,
        attributes,
        AuthorityUtils.createAuthorityList("SCOPE_message:read")
    )

    mvc.get("/endpoint") {
        with(opaqueToken().principal(principal))
    }
    ```
:::

请注意，除了使用 `opaqueToken()` 测试支持外，你还可以使用 `@MockBean`
注解来模拟 `OpaqueTokenIntrospector` Bean 本身。
