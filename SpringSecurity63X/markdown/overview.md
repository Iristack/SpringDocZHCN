我们首先来看一下 Spring Security 中 SAML 2.0 可信方（Relying
Party）认证的工作原理。 首先，可以看到与 [OAuth 2.0 登录](#oauth2login)
类似，Spring Security 会将用户重定向到第三方进行身份验证。
它通过一系列的重定向来实现这一点：

<figure>
<img src="servlet/saml2/saml2webssoauthenticationrequestfilter.png"
alt="saml2webssoauthenticationrequestfilter" />
<figcaption>重定向到断言方认证</figcaption>
</figure>

:::: note
::: title
:::

上图基于我们的
[`SecurityFilterChain`](servlet/architecture.xml#servlet-securityfilterchain)
和
[`AbstractAuthenticationProcessingFilter`](servlet/authentication/architecture.xml#servlet-authentication-abstractprocessingfilter)
图解：
::::

![number 1](icons/number_1.png) 首先，用户向 `/private`
资源发起未经认证的请求，而该资源是其无权访问的。

![number 2](icons/number_2.png) Spring Security 的
[`AuthorizationFilter`](servlet/authorization/authorize-http-requests.xml)
指示该未认证请求被拒绝，并抛出 `AccessDeniedException` 异常。

![number 3](icons/number_3.png)
由于用户缺乏授权，[`ExceptionTranslationFilter`](servlet/architecture.xml#servlet-exceptiontranslationfilter)
启动认证流程。 配置的
[`AuthenticationEntryPoint`](servlet/authentication/architecture.xml#servlet-authentication-authenticationentrypoint)
是
{security-api-url}org/springframework/security/web/authentication/LoginUrlAuthenticationEntryPoint.html\[`LoginUrlAuthenticationEntryPoint`\]
的一个实例，它会重定向到 [生成 `<saml2:AuthnRequest>`
的端点](#servlet-saml2login-sp-initiated-factory)，即
`Saml2WebSsoAuthenticationRequestFilter`。 或者，如果你已经
[配置了多个断言方](#servlet-saml2login-relyingpartyregistrationrepository)，它首先会重定向到一个选择页面。

![number 4](icons/number_4.png)
接着，`Saml2WebSsoAuthenticationRequestFilter` 使用其配置的
[`Saml2AuthenticationRequestFactory`](#servlet-saml2login-sp-initiated-factory)
创建、签名、序列化并编码一个 `<saml2:AuthnRequest>`。

![number 5](icons/number_5.png) 然后浏览器将这个 `<saml2:AuthnRequest>`
提交给断言方。 断言方尝试对用户进行认证。 如果成功，则返回一个
`<saml2:Response>` 给浏览器。

![number 6](icons/number_6.png) 浏览器随后将 `<saml2:Response>` POST
到断言消费者服务端点。

下图展示了 Spring Security 如何认证 `<saml2:Response>`。

<figure
id="servlet-saml2login-authentication-saml2webssoauthenticationfilter">
<img src="servlet/saml2/saml2webssoauthenticationfilter.png"
alt="saml2webssoauthenticationfilter" />
<figcaption>认证 <code>&lt;saml2:Response&gt;</code></figcaption>
</figure>

:::: note
::: title
:::

此图基于我们的
[`SecurityFilterChain`](servlet/architecture.xml#servlet-securityfilterchain)
图解。
::::

![number 1](icons/number_1.png) 当浏览器向应用程序提交
`<saml2:Response>` 时，它会 [委托给
`Saml2WebSsoAuthenticationFilter`](servlet/saml2/login/authentication.xml#servlet-saml2login-authenticate-responses)。
此过滤器调用其配置的 `AuthenticationConverter` 来从 `HttpServletRequest`
中提取响应以创建 `Saml2AuthenticationToken`。 该转换器还会解析
[`RelyingPartyRegistration`](#servlet-saml2login-relyingpartyregistration)
并将其提供给 `Saml2AuthenticationToken`。

![number 2](icons/number_2.png) 接下来，过滤器将令牌传递给其配置的
[`AuthenticationManager`](servlet/authentication/architecture.xml#servlet-authentication-providermanager)。
默认情况下，它使用的是
[`OpenSamlAuthenticationProvider`](#servlet-saml2login-architecture)。

![number 3](icons/number_3.png) 如果认证失败，则进入 *失败* 流程。

- [`SecurityContextHolder`](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
  将被清空。

- [`AuthenticationEntryPoint`](servlet/authentication/architecture.xml#servlet-authentication-authenticationentrypoint)
  将被调用以重新启动认证过程。

![number 4](icons/number_4.png) 如果认证成功，则进入 *成功* 流程。

- [`Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
  将被设置在
  [`SecurityContextHolder`](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
  上。

- `Saml2WebSsoAuthenticationFilter` 调用
  `FilterChain#doFilter(request,response)`
  以继续执行其余的应用程序逻辑。

# 最小依赖 {#servlet-saml2login-minimaldependencies}

SAML 2.0 服务提供商支持位于 `spring-security-saml2-service-provider`
中。 它基于 OpenSAML 库构建，因此你必须在构建配置中包含 Shibboleth Maven
仓库。 有关为何需要单独仓库的更多详细信息，请查看
[此链接](https://shibboleth.atlassian.net/wiki/spaces/DEV/pages/1123844333/Use+of+Maven+Central#Publishing-to-Maven-Central)。

::: informalexample

Maven

:   ``` xml
    <repositories>
        <!-- ... -->
        <repository>
            <id>shibboleth-releases</id>
            <name>Shibboleth Releases Repository</name>
            <url>https://build.shibboleth.net/maven/releases/</url>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
        </repository>
    </repositories>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-saml2-service-provider</artifactId>
    </dependency>
    ```

Gradle

:   ``` groovy
    repositories {
        // ...
        maven { url "https://build.shibboleth.net/nexus/content/repositories/releases/" }
    }
    dependencies {
        // ...
        implementation 'org.springframework.security:spring-security-saml2-service-provider'
    }
    ```
:::

# 最小配置 {#servlet-saml2login-minimalconfiguration}

当使用 [Spring Boot](https://spring.io/projects/spring-boot)
时，将应用程序配置为服务提供商包括两个基本步骤： . 包含所需的依赖项。 .
指定必要的断言方元数据。

:::: note
::: title
:::

此外，此配置假定你已经
[将可信方注册到你的断言方](servlet/saml2/metadata.xml#servlet-saml2login-metadata)。
::::

## 指定身份提供商元数据 {#saml2-specifying-identity-provider-metadata}

在 Spring Boot
应用程序中，要指定身份提供商的元数据，可以创建类似以下的配置：

``` yml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          adfs:
            assertingparty:
              entity-id: https://idp.example.com/issuer
              verification.credentials:
                - certificate-location: "classpath:idp.crt"
              singlesignon.url: https://idp.example.com/issuer/sso
              singlesignon.sign-request: false
```

其中：

- `https://idp.example.com/issuer` 是身份提供商发出的 SAML 响应中
  `Issuer` 属性所包含的值。

- `classpath:idp.crt` 是类路径上身份提供商用于验证 SAML 响应的证书位置。

- `https://idp.example.com/issuer/sso` 是身份提供商期望接收
  `AuthnRequest` 实例的端点。

- `adfs` 是
  [你选择的一个任意标识符](#servlet-saml2login-relyingpartyregistrationid)

就是这样！

:::: note
::: title
:::

身份提供商和断言方是同义词，服务提供商和可信方也是同义词。
这些通常分别缩写为 AP 和 RP。
::::

## 运行时预期 {#_运行时预期}

如前所述配置后，应用程序会处理任何包含 `SAMLResponse` 参数的
`POST /login/saml2/sso/{registrationId}` 请求：

``` http
POST /login/saml2/sso/adfs HTTP/1.1

SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZ...
```

有两种方式可以促使你的断言方生成 `SAMLResponse`：

- 你可以导航到你的断言方。
  它可能有一些针对每个已注册可信方的链接或按钮，你可以点击以发送
  `SAMLResponse`。

- 你可以导航到应用程序中的受保护页面------例如，`http://localhost:8080`。
  你的应用程序随后会重定向到已配置的断言方，然后断言方发送
  `SAMLResponse`。

接下来，你可以考虑跳转到：

- [SAML 2.0 登录如何与 OpenSAML 集成](#servlet-saml2login-architecture)

- [如何使用
  `Saml2AuthenticatedPrincipal`](servlet/saml2/login/authentication.xml#servlet-saml2login-authenticatedprincipal)

- [如何覆盖或替换 Spring Boot 的自动配置](#servlet-saml2login-sansboot)

# SAML 2.0 登录如何与 OpenSAML 集成 {#servlet-saml2login-architecture}

Spring Security 的 SAML 2.0 支持有几个设计目标：

- 依赖一个库来处理 SAML 2.0 操作和域对象。 为此，Spring Security 使用
  OpenSAML。

- 确保在使用 Spring Security 的 SAML 支持时不需要此库。 为此，Spring
  Security 在合同中使用的任何接口或类都保持封装。 这使得你可以将
  OpenSAML 替换为其他库或不受支持版本的 OpenSAML。

作为这两个目标的自然结果，Spring Security 的 SAML API
相对于其他模块来说非常小。 相反，像
`OpenSamlAuthenticationRequestFactory` 和
`OpenSamlAuthenticationProvider` 这样的类暴露了 `Converter`
实现，以自定义认证过程中的各个步骤。

例如，一旦你的应用程序接收到一个 `SAMLResponse` 并委托给
`Saml2WebSsoAuthenticationFilter`，该过滤器会委托给
`OpenSamlAuthenticationProvider`：

:::: formalpara
::: title
认证 OpenSAML `Response`
:::

![opensamlauthenticationprovider](servlet/saml2/opensamlauthenticationprovider.png)
::::

此图基于 [`Saml2WebSsoAuthenticationFilter`
图解](#servlet-saml2login-authentication-saml2webssoauthenticationfilter)。

![number 1](icons/number_1.png) `Saml2WebSsoAuthenticationFilter` 构造
`Saml2AuthenticationToken` 并调用
[`AuthenticationManager`](servlet/authentication/architecture.xml#servlet-authentication-providermanager)。

![number 2](icons/number_2.png)
[`AuthenticationManager`](servlet/authentication/architecture.xml#servlet-authentication-providermanager)
调用 OpenSAML 认证提供者。

![number 3](icons/number_3.png) 认证提供者将响应反序列化为 OpenSAML
`Response` 并检查其签名。 如果签名无效，认证失败。

![number 4](icons/number_4.png) 然后提供者 [解密任何
`EncryptedAssertion`
元素](servlet/saml2/login/authentication.xml#servlet-saml2login-opensamlauthenticationprovider-decryption)。
如果有任何解密失败，认证失败。

![number 5](icons/number_5.png) 接着，提供者验证响应的 `Issuer` 和
`Destination` 值。 如果它们与 `RelyingPartyRegistration`
中的内容不匹配，认证失败。

![number 6](icons/number_6.png) 之后，提供者验证每个 `Assertion`
的签名。 如果有任何签名无效，认证失败。
此外，如果响应和所有断言都没有签名，认证也会失败。
要么响应有签名，要么所有断言都有签名。

![number 7](icons/number_7.png) 然后，提供者
[,](servlet/saml2/login/authentication.xml#servlet-saml2login-opensamlauthenticationprovider-decryption)解密任何
`EncryptedID` 或 `EncryptedAttribute` 元素\]。
如果有任何解密失败，认证失败。

![number 8](icons/number_8.png) 接下来，提供者验证每个断言的 `ExpiresAt`
和 `NotBefore` 时间戳、`<Subject>` 和任何 `<AudienceRestriction>` 条件。
如果有任何验证失败，认证失败。

![number 9](icons/number_9.png) 接着，提供者取第一个断言的
`AttributeStatement` 并将其映射为 `Map<String, List<Object>>`。 同时授予
`ROLE_USER` 授权权限。

![number 10](icons/number_10.png) 最后，它从第一个断言中获取
`NameID`、属性的 `Map` 和 `GrantedAuthority`，并构造一个
`Saml2AuthenticatedPrincipal`。 然后，它将该主体和权限放入
`Saml2Authentication` 中。

最终的 `Authentication#getPrincipal` 是一个 Spring Security 的
`Saml2AuthenticatedPrincipal` 对象，而 `Authentication#getName`
映射到第一个断言的 `NameID` 元素。
`Saml2AuthenticatedPrincipal#getRelyingPartyRegistrationId` 持有 [关联
`RelyingPartyRegistration`
的标识符](#servlet-saml2login-relyingpartyregistrationid)。

## 自定义 OpenSAML 配置 {#servlet-saml2login-opensaml-customization}

任何同时使用 Spring Security 和 OpenSAML 的类都应该在类的开头静态初始化
`OpenSamlInitializationService`：

::: informalexample

Java

:   ``` java
    static {
        OpenSamlInitializationService.initialize();
    }
    ```

Kotlin

:   ``` kotlin
    companion object {
        init {
            OpenSamlInitializationService.initialize()
        }
    }
    ```
:::

这取代了 OpenSAML 的 `InitializationService#initialize`。

有时，自定义 OpenSAML 构建、编组和反编组 SAML 对象的方式可能是有价值的。
在这种情况下，你可能希望调用
`OpenSamlInitializationService#requireInitialize(Consumer)`，它为你提供对
OpenSAML 的 `XMLObjectProviderFactory` 的访问。

例如，在发送未签名的 AuthNRequest 时，你可能希望强制重新认证。
在这种情况下，你可以注册自己的 `AuthnRequestMarshaller`，如下所示：

::: informalexample

Java

:   ``` java
    static {
        OpenSamlInitializationService.requireInitialize(factory -> {
            AuthnRequestMarshaller marshaller = new AuthnRequestMarshaller() {
                @Override
                public Element marshall(XMLObject object, Element element) throws MarshallingException {
                    configureAuthnRequest((AuthnRequest) object);
                    return super.marshall(object, element);
                }

                public Element marshall(XMLObject object, Document document) throws MarshallingException {
                    configureAuthnRequest((AuthnRequest) object);
                    return super.marshall(object, document);
                }

                private void configureAuthnRequest(AuthnRequest authnRequest) {
                    authnRequest.setForceAuthn(true);
                }
            }

            factory.getMarshallerFactory().registerMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME, marshaller);
        });
    }
    ```

Kotlin

:   ``` kotlin
    companion object {
        init {
            OpenSamlInitializationService.requireInitialize {
                val marshaller = object : AuthnRequestMarshaller() {
                    override fun marshall(xmlObject: XMLObject, element: Element): Element {
                        configureAuthnRequest(xmlObject as AuthnRequest)
                        return super.marshall(xmlObject, element)
                    }

                    override fun marshall(xmlObject: XMLObject, document: Document): Element {
                        configureAuthnRequest(xmlObject as AuthnRequest)
                        return super.marshall(xmlObject, document)
                    }

                    private fun configureAuthnRequest(authnRequest: AuthnRequest) {
                        authnRequest.isForceAuthn = true
                    }
                }
                it.marshallerFactory.registerMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME, marshaller)
            }
        }
    }
    ```
:::

`requireInitialize` 方法在整个应用程序实例中只能调用一次。

# 覆盖或替换 Boot 自动配置 {#servlet-saml2login-sansboot}

Spring Boot 为可信方生成两个 `@Bean` 对象。

第一个是 `SecurityFilterChain`，它将应用程序配置为可信方。 当包含
`spring-security-saml2-service-provider` 时，`SecurityFilterChain`
看起来像这样：

:::: example
::: title
SAML 2.0 登录默认配置
:::

Java

:   ``` java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .saml2Login(withDefaults());
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
            saml2Login { }
        }
        return http.build()
    }
    ```
::::

如果应用程序没有暴露 `SecurityFilterChain` bean，Spring Boot
将暴露上述默认配置。

你可以通过在应用程序中暴露该 bean 来替换它：

:::: example
::: title
SAML 2.0 登录自定义配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class MyCustomSecurityConfiguration {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/messages/**").hasAuthority("ROLE_USER")
                    .anyRequest().authenticated()
                )
                .saml2Login(withDefaults());
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class MyCustomSecurityConfiguration {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize("/messages/**", hasAuthority("ROLE_USER"))
                    authorize(anyRequest, authenticated)
                }
                saml2Login {
                }
            }
            return http.build()
        }
    }
    ```
::::

上述示例要求任何以 `/messages/` 开头的 URL 必须具有 `USER` 角色。

第二个由 Spring Boot 创建的 `@Bean` 是
{security-api-url}org/springframework/security/saml2/provider/service/registration/RelyingPartyRegistrationRepository.html\[`RelyingPartyRegistrationRepository`\]，它表示断言方和可信方的元数据。
这包括诸如单点登录 (SSO)
端点的位置等信息，可信方在请求来自断言方的身份验证时应使用该端点。

你可以通过发布自己的 `RelyingPartyRegistrationRepository` bean
来覆盖默认设置。 例如，你可以通过访问其元数据端点来查找断言方的配置：

:::: example
::: title
可信方注册存储库
:::

Java

:   ``` java
    @Value("${metadata.location}")
    String assertingPartyMetadataLocation;

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        RelyingPartyRegistration registration = RelyingPartyRegistrations
                .fromMetadataLocation(assertingPartyMetadataLocation)
                .registrationId("example")
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }
    ```

Kotlin

:   ``` kotlin
    @Value("\${metadata.location}")
    var assertingPartyMetadataLocation: String? = null

    @Bean
    open fun relyingPartyRegistrations(): RelyingPartyRegistrationRepository? {
        val registration = RelyingPartyRegistrations
            .fromMetadataLocation(assertingPartyMetadataLocation)
            .registrationId("example")
            .build()
        return InMemoryRelyingPartyRegistrationRepository(registration)
    }
    ```
::::

:::: {#servlet-saml2login-relyingpartyregistrationid .note}
::: title
:::

`registrationId` 是你选择用来区分不同注册的任意值。
::::

或者，你可以手动提供每个细节：

:::: example
::: title
可信方注册存储库手动配置
:::

Java

:   ``` java
    @Value("${verification.key}")
    File verificationKey;

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
        X509Certificate certificate = X509Support.decodeCertificate(this.verificationKey);
        Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId("example")
                .assertingPartyDetails(party -> party
                    .entityId("https://idp.example.com/issuer")
                    .singleSignOnServiceLocation("https://idp.example.com/SSO.saml2")
                    .wantAuthnRequestsSigned(false)
                    .verificationX509Credentials(c -> c.add(credential))
                )
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }
    ```

Kotlin

:   ``` kotlin
    @Value("\${verification.key}")
    var verificationKey: File? = null

    @Bean
    open fun relyingPartyRegistrations(): RelyingPartyRegistrationRepository {
        val certificate: X509Certificate? = X509Support.decodeCertificate(verificationKey!!)
        val credential: Saml2X509Credential = Saml2X509Credential.verification(certificate)
        val registration = RelyingPartyRegistration
            .withRegistrationId("example")
            .assertingPartyDetails { party: AssertingPartyDetails.Builder ->
                party
                    .entityId("https://idp.example.com/issuer")
                    .singleSignOnServiceLocation("https://idp.example.com/SSO.saml2")
                    .wantAuthnRequestsSigned(false)
                    .verificationX509Credentials { c: MutableCollection<Saml2X509Credential?> ->
                        c.add(
                            credential
                        )
                    }
            }
            .build()
        return InMemoryRelyingPartyRegistrationRepository(registration)
    }
    ```
::::

:::: note
::: title
:::

`X509Support` 是一个 OpenSAML 类，在前面的代码片段中为了简洁而使用。
::::

或者，你可以直接使用 DSL 来连接存储库，这也覆盖了自动配置的
`SecurityFilterChain`：

:::: example
::: title
自定义可信方注册 DSL
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class MyCustomSecurityConfiguration {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/messages/**").hasAuthority("ROLE_USER")
                    .anyRequest().authenticated()
                )
                .saml2Login(saml2 -> saml2
                    .relyingPartyRegistrationRepository(relyingPartyRegistrations())
                );
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class MyCustomSecurityConfiguration {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize("/messages/**", hasAuthority("ROLE_USER"))
                    authorize(anyRequest, authenticated)
                }
                saml2Login {
                    relyingPartyRegistrationRepository = relyingPartyRegistrations()
                }
            }
            return http.build()
        }
    }
    ```
::::

:::: note
::: title
:::

通过在 `RelyingPartyRegistrationRepository`
中注册多个可信方，可信方可实现多租户。
::::

# RelyingPartyRegistration {#servlet-saml2login-relyingpartyregistration}

{security-api-url}org/springframework/security/saml2/provider/service/registration/RelyingPartyRegistration.html\[`RelyingPartyRegistration`\]
实例代表了一个可信方与断言方元数据之间的链接。

在 `RelyingPartyRegistration` 中，你可以提供可信方的元数据，比如它的
`Issuer` 值、它期望 SAML
响应发送到的位置以及它拥有的用于签名或解密负载的凭据。

此外，你还可以提供断言方的元数据，比如它的 `Issuer` 值、它期望
AuthnRequests
发送到的位置以及它拥有的公钥凭据，以便可信方用于验证或加密负载。

以下是大多数设置所需的最小 `RelyingPartyRegistration`：

::: informalexample

Java

:   ``` java
    RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
            .fromMetadataLocation("https://ap.example.org/metadata")
            .registrationId("my-id")
            .build();
    ```

Kotlin

:   ``` kotlin
    val relyingPartyRegistration = RelyingPartyRegistrations
        .fromMetadataLocation("https://ap.example.org/metadata")
        .registrationId("my-id")
        .build()
    ```
:::

请注意，你也可以从任意 `InputStream` 源创建 `RelyingPartyRegistration`。
一个例子是当元数据存储在数据库中时：

``` java
String xml = fromDatabase();
try (InputStream source = new ByteArrayInputStream(xml.getBytes())) {
    RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
            .fromMetadata(source)
            .registrationId("my-id")
            .build();
}
```

更复杂的设置也是可能的：

::: informalexample

Java

:   ``` java
    RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration.withRegistrationId("my-id")
            .entityId("{baseUrl}/{registrationId}")
            .decryptionX509Credentials(c -> c.add(relyingPartyDecryptingCredential()))
            .assertionConsumerServiceLocation("/my-login-endpoint/{registrationId}")
            .assertingPartyDetails(party -> party
                    .entityId("https://ap.example.org")
                    .verificationX509Credentials(c -> c.add(assertingPartyVerifyingCredential()))
                    .singleSignOnServiceLocation("https://ap.example.org/SSO.saml2")
            )
            .build();
    ```

Kotlin

:   ``` kotlin
    val relyingPartyRegistration =
        RelyingPartyRegistration.withRegistrationId("my-id")
            .entityId("{baseUrl}/{registrationId}")
            .decryptionX509Credentials { c: MutableCollection<Saml2X509Credential?> ->
                c.add(relyingPartyDecryptingCredential())
            }
            .assertionConsumerServiceLocation("/my-login-endpoint/{registrationId}")
            .assertingPartyDetails { party -> party
                    .entityId("https://ap.example.org")
                    .verificationX509Credentials { c -> c.add(assertingPartyVerifyingCredential()) }
                    .singleSignOnServiceLocation("https://ap.example.org/SSO.saml2")
            }
            .build()
    ```
:::

:::: tip
::: title
:::

顶级元数据方法是关于可信方的详细信息。 `assertingPartyDetails`
内部的方法是关于断言方的详细信息。
::::

:::: note
::: title
:::

可信方期望接收 SAML 响应的位置称为断言消费者服务位置。
::::

可信方的 `entityId` 默认值为
`{baseUrl}/saml2/service-provider-metadata/{registrationId}`。
这是配置断言方以了解你的可信方所需的确切值。

`assertionConsumerServiceLocation` 的默认值是
`/login/saml2/sso/{registrationId}`。 默认情况下，它在过滤器链中映射到
[`Saml2WebSsoAuthenticationFilter`](#servlet-saml2login-authentication-saml2webssoauthenticationfilter)。

## URI 模式 {#servlet-saml2login-rpr-uripatterns}

你可能注意到了前面示例中的 `{baseUrl}` 和 `{registrationId}` 占位符。

这些占位符对于生成 URI 非常有用。因此，可信方的 `entityId` 和
`assertionConsumerServiceLocation` 支持以下占位符：

- `baseUrl` - 部署应用程序的方案、主机和端口

- `registrationId` - 此可信方的注册 ID

- `baseScheme` - 部署应用程序的方案

- `baseHost` - 部署应用程序的主机

- `basePort` - 部署应用程序的端口

例如，之前定义的 `assertionConsumerServiceLocation` 是：

`/my-login-endpoint/{registrationId}`

在部署的应用程序中，它转换为：

`/my-login-endpoint/adfs`

之前显示的 `entityId` 定义为：

`{baseUrl}/{registrationId}`

在部署的应用程序中，这转换为：

`https://rp.example.com/adfs`

主要的 URI 模式如下：

- `/saml2/authenticate/{registrationId}` - 根据该
  `RelyingPartyRegistration` 的配置生成 `<saml2:AuthnRequest>`
  并将其发送到断言方的端点；xref:servlet/saml2/login/authentication-requests.adoc

- `/login/saml2/sso/` - 认证断言方 `<saml2:Response>`
  的端点；如果需要，`RelyingPartyRegistration`
  会根据先前的认证状态或响应的发行者查找；也支持
  `/login/saml2/sso/{registrationId}`；xref:servlet/saml2/login/authentication.adoc

- `/logout/saml2/sso` - 处理 `<saml2:LogoutRequest>` 和
  `<saml2:LogoutResponse>`
  负载的端点；如果需要，`RelyingPartyRegistration`
  会根据当前登录用户的认证状态或请求的发行者查找；也支持
  `/logout/saml2/slo/{registrationId}`；xref:servlet/saml2/logout.adoc

- `/saml2/metadata` - 一组 `RelyingPartyRegistration`s 的
  [可信方元数据](servlet/saml2/metadata.xml)；也支持
  `/saml2/metadata/{registrationId}` 或
  `/saml2/service-provider-metadata/{registrationId}` 以获取特定的
  `RelyingPartyRegistration`

由于 `registrationId` 是 `RelyingPartyRegistration`
的主要标识符，因此在未经认证的情况下需要在 URL 中包含它。
如果你出于某种原因希望从 URL 中移除 `registrationId`，你可以 [指定一个
`RelyingPartyRegistrationResolver`](#servlet-saml2login-rpr-relyingpartyregistrationresolver)
告诉 Spring Security 如何查找 `registrationId`。

## 凭据 {#servlet-saml2login-rpr-credentials}

在前面展示的示例中，你也可能注意到了所使用的凭据。

通常，可信方使用相同的密钥来签名和解密负载。
或者，它可以使用相同的密钥来验证和加密负载。

正因为如此，Spring Security 提供了 `Saml2X509Credential`，这是一个特定于
SAML 的凭据，简化了为不同用例配置相同密钥的过程。

至少，你需要从断言方获取一个证书，以便能够验证断言方签名的响应。

要构造一个可用于验证来自断言方的断言的
`Saml2X509Credential`，你可以加载文件并使用 `CertificateFactory`：

::: informalexample

Java

:   ``` java
    Resource resource = new ClassPathResource("ap.crt");
    try (InputStream is = resource.getInputStream()) {
        X509Certificate certificate = (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(is);
        return Saml2X509Credential.verification(certificate);
    }
    ```

Kotlin

:   ``` kotlin
    val resource = ClassPathResource("ap.crt")
    resource.inputStream.use {
        return Saml2X509Credential.verification(
            CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate?
        )
    }
    ```
:::

假设断言方还将加密断言。
在这种情况下，可信方需要一个私钥来解密加密的值。

在这种情况下，你需要一个 `RSAPrivateKey` 及其对应的 `X509Certificate`。
你可以使用 Spring Security 的 `RsaKeyConverters`
工具类加载前者，并以前面提到的方式加载后者：

::: informalexample

Java

:   ``` java
    X509Certificate certificate = relyingPartyDecryptionCertificate();
    Resource resource = new ClassPathResource("rp.crt");
    try (InputStream is = resource.getInputStream()) {
        RSAPrivateKey rsa = RsaKeyConverters.pkcs8().convert(is);
        return Saml2X509Credential.decryption(rsa, certificate);
    }
    ```

Kotlin

:   ``` kotlin
    val certificate: X509Certificate = relyingPartyDecryptionCertificate()
    val resource = ClassPathResource("rp.crt")
    resource.inputStream.use {
        val rsa: RSAPrivateKey = RsaKeyConverters.pkcs8().convert(it)
        return Saml2X509Credential.decryption(rsa, certificate)
    }
    ```
:::

:::: tip
::: title
:::

当你将这些文件的位置指定为适当的 Spring Boot 属性时，Spring Boot
会为你执行这些转换。
::::

## 重复的可信方配置 {#servlet-saml2login-rpr-duplicated}

当应用程序使用多个断言方时，一些配置会在 `RelyingPartyRegistration`
实例之间重复：

- 可信方的 `entityId`

- 其 `assertionConsumerServiceLocation`

- 其凭据 ------ 例如，其签名或解密凭据

这种设置可能使某些身份提供商比其他身份提供商更容易轮换凭据。

可以通过几种不同的方式缓解这种重复。

首先，在 YAML 中，这可以通过引用缓解：

``` yaml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          okta:
            signing.credentials: &relying-party-credentials
              - private-key-location: classpath:rp.key
                certificate-location: classpath:rp.crt
            assertingparty:
              entity-id: ...
          azure:
            signing.credentials: *relying-party-credentials
            assertingparty:
              entity-id: ...
```

其次，在数据库中，你无需复制 `RelyingPartyRegistration` 的模型。

第三，在 Java 中，你可以创建一个自定义配置方法：

::: informalexample

Java

:   ``` java
    private RelyingPartyRegistration.Builder
            addRelyingPartyDetails(RelyingPartyRegistration.Builder builder) {

        Saml2X509Credential signingCredential = ...
        builder.signingX509Credentials(c -> c.addAll(signingCredential));
        // ... 其他可信方配置
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        RelyingPartyRegistration okta = addRelyingPartyDetails(
                RelyingPartyRegistrations
                    .fromMetadataLocation(oktaMetadataUrl)
                    .registrationId("okta")).build();

        RelyingPartyRegistration azure = addRelyingPartyDetails(
                RelyingPartyRegistrations
                    .fromMetadataLocation(oktaMetadataUrl)
                    .registrationId("azure")).build();

        return new InMemoryRelyingPartyRegistrationRepository(okta, azure);
    }
    ```

Kotlin

:   ``` kotlin
    private fun addRelyingPartyDetails(builder: RelyingPartyRegistration.Builder): RelyingPartyRegistration.Builder {
        val signingCredential: Saml2X509Credential = ...
        builder.signingX509Credentials { c: MutableCollection<Saml2X509Credential?> ->
            c.add(
                signingCredential
            )
        }
        // ... 其他可信方配置
    }

    @Bean
    open fun relyingPartyRegistrations(): RelyingPartyRegistrationRepository? {
        val okta = addRelyingPartyDetails(
            RelyingPartyRegistrations
                .fromMetadataLocation(oktaMetadataUrl)
                .registrationId("okta")
        ).build()
        val azure = addRelyingPartyDetails(
            RelyingPartyRegistrations
                .fromMetadataLocation(oktaMetadataUrl)
                .registrationId("azure")
        ).build()
        return InMemoryRelyingPartyRegistrationRepository(okta, azure)
    }
    ```
:::

## 从请求解析 `RelyingPartyRegistration` {#servlet-saml2login-rpr-relyingpartyregistrationresolver}

如前所述，Spring Security 通过在 URI 路径中查找注册 ID 来解析
`RelyingPartyRegistration`。

根据使用场景的不同，也有多种其他策略来推导出它。例如：

- 对于处理 `<saml2:Response>`，`RelyingPartyRegistration` 会从相关的
  `<saml2:AuthRequest>` 或 `<saml2:Response#Issuer>` 元素中查找

- 对于处理 `<saml2:LogoutRequest>`，`RelyingPartyRegistration`
  会从当前登录用户或 `<saml2:LogoutRequest#Issuer>` 元素中查找

- 对于发布元数据，`` RelyingPartyRegistration`s 会从任何实现了 `Iterable<RelyingPartyRegistration> ``
  的存储库中查找

当需要调整时，你可以转向针对这些端点的具体组件，以定制此行为：

- 对于 SAML 响应，自定义 `AuthenticationConverter`

- 对于注销请求，自定义 `Saml2LogoutRequestValidatorParametersResolver`

- 对于元数据，自定义 `Saml2MetadataResponseResolver`

## 联合登录 {#federating-saml2-login}

SAML 2.0 的一种常见安排是一个身份提供商拥有多个断言方。
在这种情况下，身份提供商的元数据端点返回多个 `<md:IDPSSODescriptor>`
元素。

这些多个断言方可以通过一次调用 `RelyingPartyRegistrations`
来访问，如下所示：

::: informalexample

Java

:   ``` java
    Collection<RelyingPartyRegistration> registrations = RelyingPartyRegistrations
            .collectionFromMetadataLocation("https://example.org/saml2/idp/metadata.xml")
            .stream().map((builder) -> builder
                .registrationId(UUID.randomUUID().toString())
                .entityId("https://example.org/saml2/sp")
                .build()
            )
            .collect(Collectors.toList());
    ```

Kotlin

:   ``` kotlin
    var registrations: Collection<RelyingPartyRegistration> = RelyingPartyRegistrations
            .collectionFromMetadataLocation("https://example.org/saml2/idp/metadata.xml")
            .stream().map { builder : RelyingPartyRegistration.Builder -> builder
                .registrationId(UUID.randomUUID().toString())
                .entityId("https://example.org/saml2/sp")
                .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso")
                .build()
            }
            .collect(Collectors.toList())
    ```
:::

请注意，由于注册 ID 设置为随机值，这会使某些 SAML 2.0 端点变得不可预测。
有几种方法可以解决这个问题；让我们专注于适合联合使用场景的一种方法。

在许多联合情况下，所有断言方共享服务提供商配置。 鉴于 Spring Security
默认会在服务提供商元数据中包含 `registrationId`，另一步骤是更改相应的
URI 以排除 `registrationId`，你可以在上面的示例中看到，`entityId` 和
`assertionConsumerServiceLocation` 已经配置为静态端点。

你可以在我们的 `saml-extension-federation`
示例中看到完整的实现：{gh-samples-url}/servlet/spring-boot/java/saml2/saml-extension-federation。

## 使用 Spring Security SAML 扩展 URI {#using-spring-security-saml-extension-uris}

如果你正在从 Spring Security SAML 扩展迁移，那么配置你的应用程序以使用
SAML 扩展 URI 默认值可能会有一些好处。

有关更多信息，请参阅我们的 `custom-urls`
示例：{gh-samples-url}/servlet/spring-boot/java/saml2/custom-urls 和
`saml-extension-federation`
示例：{gh-samples-url}/servlet/spring-boot/java/saml2/saml-extension-federation。
