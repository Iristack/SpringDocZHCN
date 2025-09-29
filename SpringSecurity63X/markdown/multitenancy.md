# 同时支持 JWT 和不透明令牌 {#oauth2reourceserver-opaqueandjwt}

在某些情况下，你可能需要同时处理两种类型的令牌。
例如，你可能支持多个租户，其中一个租户签发 JWT
令牌，而另一个租户使用不透明令牌。

如果这个决策必须在请求时做出，则可以使用 `AuthenticationManagerResolver`
来实现，如下所示：

::: informalexample

Java

:   ``` java
    @Bean
    AuthenticationManagerResolver<HttpServletRequest> tokenAuthenticationManagerResolver
            (JwtDecoder jwtDecoder, OpaqueTokenIntrospector opaqueTokenIntrospector) {
        AuthenticationManager jwt = new ProviderManager(new JwtAuthenticationProvider(jwtDecoder));
        AuthenticationManager opaqueToken = new ProviderManager(
                new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector));
        return (request) -> useJwt(request) ? jwt : opaqueToken;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun tokenAuthenticationManagerResolver
            (jwtDecoder: JwtDecoder, opaqueTokenIntrospector: OpaqueTokenIntrospector):
            AuthenticationManagerResolver<HttpServletRequest> {
        val jwt = ProviderManager(JwtAuthenticationProvider(jwtDecoder))
        val opaqueToken = ProviderManager(OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector));

        return AuthenticationManagerResolver { request ->
            if (useJwt(request)) {
                jwt
            } else {
                opaqueToken
            }
        }
    }
    ```
:::

:::: note
::: title
:::

`useJwt(HttpServletRequest)`
方法的实现通常依赖于自定义请求信息，比如路径。
::::

然后，在 DSL 中指定此 `AuthenticationManagerResolver`：

:::: example
::: title
Authentication Manager Resolver
:::

Java

:   ``` java
    http
        .authorizeHttpRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .authenticationManagerResolver(this.tokenAuthenticationManagerResolver)
        );
    ```

Kotlin

:   ``` kotlin
    http {
        authorizeRequests {
            authorize(anyRequest, authenticated)
        }
        oauth2ResourceServer {
            authenticationManagerResolver = tokenAuthenticationManagerResolver()
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <oauth2-resource-server authentication-manager-resolver-ref="tokenAuthenticationManagerResolver"/>
    </http>
    ```
::::

# 多租户 {#oauth2resourceserver-multitenancy}

当存在多种策略用于验证承载令牌（Bearer
Token），并以某个租户标识符作为区分依据时，该资源服务器即被视为多租户。

例如，你的资源服务器可能接受来自两个不同授权服务器的承载令牌；
或者你的授权服务器代表了多个不同的发行方（issuer）。

在这两种场景下，都需要完成两件事，并且每种方式的选择都会带来相应的权衡：

1.  解析租户（Resolve the tenant）

2.  传播租户（Propagate the tenant）

## 根据声明（Claim）解析租户 {#_根据声明claim解析租户}

一种区分租户的方式是通过 issuer 声明。由于 issuer 声明通常随签名的 JWT
一起提供，因此可以使用 `JwtIssuerAuthenticationManagerResolver`
实现，如下所示：

:::: example
::: title
Multi-tenancy Tenant by JWT Claim
:::

Java

:   ``` java
    JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
        .fromTrustedIssuers("https://idp.example.org/issuerOne", "https://idp.example.org/issuerTwo");

    http
        .authorizeHttpRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .authenticationManagerResolver(authenticationManagerResolver)
        );
    ```

Kotlin

:   ``` kotlin
    val customAuthenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
        .fromTrustedIssuers("https://idp.example.org/issuerOne", "https://idp.example.org/issuerTwo")
    http {
        authorizeRequests {
            authorize(anyRequest, authenticated)
        }
        oauth2ResourceServer {
            authenticationManagerResolver = customAuthenticationManagerResolver
        }
    }
    ```

Xml

:   ``` xml
    <http>
        <oauth2-resource-server authentication-manager-resolver-ref="authenticationManagerResolver"/>
    </http>

    <bean id="authenticationManagerResolver"
            class="org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver">
        <constructor-arg>
            <list>
                <value>https://idp.example.org/issuerOne</value>
                <value>https://idp.example.org/issuerTwo</value>
            </list>
        </constructor-arg>
    </bean>
    ```
::::

这种方式的优点在于，issuer 端点是惰性加载的。实际上，对应的
`JwtAuthenticationProvider` 只有在收到对应 issuer
的第一个请求时才会被实例化。这使得应用程序启动时无需依赖这些授权服务器是否已上线或可用。

### 动态租户 {#_动态租户}

当然，你可能不希望每次新增租户时都重启应用。此时，你可以将
`JwtIssuerAuthenticationManagerResolver` 配置为一个包含
`AuthenticationManager` 实例的仓库，可以在运行时对其进行修改，如下所示：

::: informalexample

Java

:   ``` java
    private void addManager(Map<String, AuthenticationManager> authenticationManagers, String issuer) {
        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider
                (JwtDecoders.fromIssuerLocation(issuer));
        authenticationManagers.put(issuer, authenticationProvider::authenticate);
    }

    // ...

    JwtIssuerAuthenticationManagerResolver authenticationManagerResolver =
            new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);

    http
        .authorizeHttpRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .authenticationManagerResolver(authenticationManagerResolver)
        );
    ```

Kotlin

:   ``` kotlin
    private fun addManager(authenticationManagers: MutableMap<String, AuthenticationManager>, issuer: String) {
        val authenticationProvider = JwtAuthenticationProvider(JwtDecoders.fromIssuerLocation(issuer))
        authenticationManagers[issuer] = AuthenticationManager {
            authentication: Authentication? -> authenticationProvider.authenticate(authentication)
        }
    }

    // ...

    val customAuthenticationManagerResolver: JwtIssuerAuthenticationManagerResolver =
        JwtIssuerAuthenticationManagerResolver(authenticationManagers::get)
    http {
        authorizeRequests {
            authorize(anyRequest, authenticated)
        }
        oauth2ResourceServer {
            authenticationManagerResolver = customAuthenticationManagerResolver
        }
    }
    ```
:::

在这种情况下，你通过一个根据 issuer 获取 `AuthenticationManager`
的策略来构造
`JwtIssuerAuthenticationManagerResolver`。这种方法允许我们在运行时向仓库（如示例中的
`Map`）添加或删除元素。

:::: note
::: title
:::

直接接受任意 issuer 并从中构建 `AuthenticationManager`
是不安全的。issuer 必须来自可信来源（例如预定义的允许 issuer
列表）才能被代码验证。
::::

### 仅解析一次声明（Claim） {#_仅解析一次声明claim}

你可能已经注意到，虽然这种策略很简单，但其代价是 JWT 会在
`AuthenticationManagerResolver` 中被解析一次，随后在请求流程中又被
[`JwtDecoder`](servlet/oauth2/resource-server/jwt.xml#oauth2resourceserver-jwt-architecture-jwtdecoder)
再次解析。

可以通过直接配置
[`JwtDecoder`](servlet/oauth2/resource-server/jwt.xml#oauth2resourceserver-jwt-architecture-jwtdecoder)
使用 Nimbus 提供的 `JWTClaimsSetAwareJWSKeySelector`
来缓解这一额外解析开销：

::: informalexample

Java

:   ``` java
    @Component
    public class TenantJWSKeySelector
        implements JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

        private final TenantRepository tenants; 
        private final Map<String, JWSKeySelector<SecurityContext>> selectors = new ConcurrentHashMap<>(); 

        public TenantJWSKeySelector(TenantRepository tenants) {
            this.tenants = tenants;
        }

        @Override
        public List<? extends Key> selectKeys(JWSHeader jwsHeader, JWTClaimsSet jwtClaimsSet, SecurityContext securityContext)
                throws KeySourceException {
            return this.selectors.computeIfAbsent(toTenant(jwtClaimsSet), this::fromTenant)
                    .selectJWSKeys(jwsHeader, securityContext);
        }

        private String toTenant(JWTClaimsSet claimSet) {
            return (String) claimSet.getClaim("iss");
        }

        private JWSKeySelector<SecurityContext> fromTenant(String tenant) {
            return Optional.ofNullable(this.tenants.findById(tenant)) 
                    .map(t -> t.getAttrbute("jwks_uri"))
                    .map(this::fromUri)
                    .orElseThrow(() -> new IllegalArgumentException("unknown tenant"));
        }

        private JWSKeySelector<SecurityContext> fromUri(String uri) {
            try {
                return JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(new URL(uri)); 
            } catch (Exception ex) {
                throw new IllegalArgumentException(ex);
            }
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    class TenantJWSKeySelector(tenants: TenantRepository) : JWTClaimsSetAwareJWSKeySelector<SecurityContext> {
        private val tenants: TenantRepository 
        private val selectors: MutableMap<String, JWSKeySelector<SecurityContext>> = ConcurrentHashMap() 

        init {
            this.tenants = tenants
        }

        fun selectKeys(jwsHeader: JWSHeader?, jwtClaimsSet: JWTClaimsSet, securityContext: SecurityContext): List<Key?> {
            return selectors.computeIfAbsent(toTenant(jwtClaimsSet)) { tenant: String -> fromTenant(tenant) }
                    .selectJWSKeys(jwsHeader, securityContext)
        }

        private fun toTenant(claimSet: JWTClaimsSet): String {
            return claimSet.getClaim("iss") as String
        }

        private fun fromTenant(tenant: String): JWSKeySelector<SecurityContext> {
            return Optional.ofNullable(this.tenants.findById(tenant)) 
                    .map { t -> t.getAttrbute("jwks_uri") }
                    .map { uri: String -> fromUri(uri) }
                    .orElseThrow { IllegalArgumentException("unknown tenant") }
        }

        private fun fromUri(uri: String): JWSKeySelector<SecurityContext?> {
            return try {
                JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(URL(uri)) 
            } catch (ex: Exception) {
                throw IllegalArgumentException(ex)
            }
        }
    }
    ```
:::

- 租户信息的假想数据源

- 按租户标识符缓存 `JWKKeySelector` 的映射表

- 查找租户比动态计算 JWK Set
  地址更安全------查找过程相当于一个"允许租户"白名单

- 通过 JWK Set 端点返回的密钥类型创建 `JWSKeySelector` ------
  此处的懒加载意味着你无需在启动时配置所有租户

上述密钥选择器是由多个密钥选择器组合而成，它会根据 JWT 中的 `iss`
声明决定使用哪一个密钥选择器。

:::: note
::: title
:::

使用此方法时，请确保授权服务器配置为将声明集包含在令牌签名中。否则，无法保证
issuer 未被恶意篡改。
::::

接下来，我们可以构造一个 `JWTProcessor`：

::: informalexample

Java

:   ``` java
    @Bean
    JWTProcessor jwtProcessor(JWTClaimsSetAwareJWSKeySelector keySelector) {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                new DefaultJWTProcessor();
        jwtProcessor.setJWTClaimSetJWSKeySelector(keySelector);
        return jwtProcessor;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun jwtProcessor(keySelector: JWTClaimsSetAwareJWSKeySelector<SecurityContext>): JWTProcessor<SecurityContext> {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>()
        jwtProcessor.jwtClaimsSetAwareJWSKeySelector = keySelector
        return jwtProcessor
    }
    ```
:::

正如你现在所看到的，将租户感知能力下移到这一层级的代价是更多的配置工作。我们还差最后一步。

接下来，我们仍需确保对 issuer 进行验证。但由于每个 JWT 的 issuer
可能不同，因此你也需要一个支持多租户的验证器：

::: informalexample

Java

:   ``` java
    @Component
    public class TenantJwtIssuerValidator implements OAuth2TokenValidator<Jwt> {
        private final TenantRepository tenants;

        private final OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "The iss claim is not valid",
                "https://tools.ietf.org/html/rfc6750#section-3.1");

        public TenantJwtIssuerValidator(TenantRepository tenants) {
            this.tenants = tenants;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            if(this.tenants.findById(token.getIssuer()) != null) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(this.error);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    class TenantJwtIssuerValidator(private val tenants: TenantRepository) : OAuth2TokenValidator<Jwt> {
        private val error: OAuth2Error = OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "The iss claim is not valid",
                "https://tools.ietf.org/html/rfc6750#section-3.1")

        override fun validate(token: Jwt): OAuth2TokenValidatorResult {
            return if (tenants.findById(token.issuer) != null)
                OAuth2TokenValidatorResult.success() else OAuth2TokenValidatorResult.failure(error)
        }
    }
    ```
:::

现在我们已经有了一个支持多租户的处理器和验证器，可以继续创建我们的
[`JwtDecoder`](servlet/oauth2/resource-server/jwt.xml#oauth2resourceserver-jwt-architecture-jwtdecoder)：

::: informalexample

Java

:   ``` java
    @Bean
    JwtDecoder jwtDecoder(JWTProcessor jwtProcessor, OAuth2TokenValidator<Jwt> jwtValidator) {
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>
                (JwtValidators.createDefault(), jwtValidator);
        decoder.setJwtValidator(validator);
        return decoder;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun jwtDecoder(jwtProcessor: JWTProcessor<SecurityContext>?, jwtValidator: OAuth2TokenValidator<Jwt>?): JwtDecoder {
        val decoder = NimbusJwtDecoder(jwtProcessor)
        val validator: OAuth2TokenValidator<Jwt> = DelegatingOAuth2TokenValidator(JwtValidators.createDefault(), jwtValidator)
        decoder.setJwtValidator(validator)
        return decoder
    }
    ```
:::

关于"解析租户"的讨论到此结束。

如果你选择通过非 JWT
声明的方式来解析租户（例如子域名），那么你也需要用相同的方式处理下游资源服务器。例如，若你是通过子域名识别租户，则下游资源服务器也应使用相同的子域名进行访问。

然而，如果你是通过承载令牌中的声明来解析租户，请继续阅读以了解 [Spring
Security
对承载令牌传播的支持](servlet/oauth2/resource-server/bearer-tokens.xml#oauth2resourceserver-bearertoken-resolver)。
