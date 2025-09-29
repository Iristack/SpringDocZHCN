# Spring Boot 示例 {#oauth2login-sample-boot}

Spring Boot 为 OAuth 2.0 登录提供了完整的自动配置功能。

本节介绍如何使用 *Google* 作为 *认证提供者* 来配置
{gh-samples-url}/servlet/spring-boot/java/oauth2/login\[**OAuth 2.0
登录示例**\]，涵盖以下主题：

- [初始设置](#oauth2login-sample-initial-setup)

- [设置重定向 URI](#oauth2login-sample-redirect-uri)

- [配置 application.yml](#oauth2login-sample-application-config)

- [启动应用程序](#oauth2login-sample-boot-application)

## 初始设置 {#oauth2login-sample-initial-setup}

要使用 Google 的 OAuth 2.0 认证系统进行登录，您必须在 Google API
控制台中创建一个项目以获取 OAuth 2.0 凭据。

:::: note
::: title
:::

[Google 的 OAuth 2.0
实现](https://developers.google.com/identity/protocols/OpenIDConnect)
符合 [OpenID Connect 1.0](https://openid.net/connect/) 规范，并且是经过
[OpenID 认证](https://openid.net/certification/)的。
::::

请按照 [OpenID
Connect](https://developers.google.com/identity/protocols/OpenIDConnect)
页面中的说明操作，从 "Setting up OAuth 2.0"（设置 OAuth 2.0）部分开始。

完成\"\`获取 OAuth 2.0 凭据\`\"的说明后，您将获得一个新的 OAuth
客户端，其凭据包括客户端 ID 和客户端密钥。

## 设置重定向 URI {#oauth2login-sample-redirect-uri}

重定向 URI 是应用程序中的路径，在最终用户通过 Google
身份验证并在同意页面上授权给 OAuth
客户端（[上一步创建的](#oauth2login-sample-initial-setup)）之后，用户的用户代理会被重定向回此路径。

在\"\`设置重定向 URI\`\"子部分中，请确保 **授权重定向 URI** 字段设置为
`http://localhost:8080/login/oauth2/code/google`。

:::: tip
::: title
:::

默认的重定向 URI 模板是 `{baseUrl}/login/oauth2/code/{registrationId}`。
`registrationId` 是
[`ClientRegistration`](servlet/oauth2/client/index.xml#oauth2Client-client-registration)
的唯一标识符。
::::

:::: important
::: title
:::

如果 OAuth 客户端运行在代理服务器后面，您应检查
[代理服务器配置](features/exploits/http.xml#http-proxy-server)，以确保应用程序正确配置。
此外，请参阅支持的 [ `URI`
模板变量](servlet/oauth2/client/authorization-grants.xml#oauth2Client-auth-code-redirect-uri)
用于 `redirect-uri`。
::::

## 配置 application.yml {#oauth2login-sample-application-config}

现在您已拥有与 Google 关联的新 OAuth 客户端，需要配置应用程序以使用该
OAuth 客户端进行 *认证流程*。为此：

1.  打开 `application.yml` 文件并设置如下配置：

    ``` yaml
    spring:
      security:
        oauth2:
          client:
            registration:   
              google:   
                client-id: google-client-id
                client-secret: google-client-secret
    ```

    :::: {}
    ::: title
    OAuth 客户端属性
    :::

    - `spring.security.oauth2.client.registration` 是 OAuth
      客户端属性的基本前缀。

    - 在基本属性前缀之后是
      [`ClientRegistration`](servlet/oauth2/client/index.xml#oauth2Client-client-registration)
      的 ID，例如 Google。
    ::::

2.  将 `client-id` 和 `client-secret` 属性的值替换为您之前创建的 OAuth
    2.0 凭据。

## 启动应用程序 {#oauth2login-sample-boot-application}

启动 Spring Boot 示例并访问 `http://localhost:8080`。
此时会重定向到默认的 *自动生成* 登录页面，该页面显示一个指向 Google
的链接。

点击 Google 链接，您将被重定向至 Google 进行身份验证。

使用您的 Google 账户凭据进行身份验证后，您将看到同意屏幕。
该同意屏幕要求您允许或拒绝访问之前创建的 OAuth 客户端。 点击 **允许**
授权 OAuth 客户端访问您的电子邮件地址和基本个人资料信息。

此时，OAuth 客户端会从 [UserInfo
端点](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
获取您的电子邮件地址和基本个人资料信息，并建立一个已认证的会话。

# Spring Boot 属性映射 {#oauth2login-boot-property-mappings}

下表列出了 Spring Boot OAuth 客户端属性与
[ClientRegistration](servlet/oauth2/client/index.xml#oauth2Client-client-registration)
属性之间的映射关系。

+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| Spring Boot                                                                                | ClientRegistration                                       |
+============================================================================================+==========================================================+
| `spring.security.oauth2.client.registration.[registrationId]`                              | `registrationId`                                         |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.registration.[registrationId].client-id`                    | `clientId`                                               |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.registration.[registrationId].client-secret`                | `clientSecret`                                           |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.registration.[registrationId].client-authentication-method` | `clientAuthenticationMethod`                             |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.registration.[registrationId].authorization-grant-type`     | `authorizationGrantType`                                 |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.registration.[registrationId].redirect-uri`                 | `redirectUri`                                            |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.registration.[registrationId].scope`                        | `scopes`                                                 |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.registration.[registrationId].client-name`                  | `clientName`                                             |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.provider.[providerId].authorization-uri`                    | `providerDetails.authorizationUri`                       |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.provider.[providerId].token-uri`                            | `providerDetails.tokenUri`                               |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.provider.[providerId].jwk-set-uri`                          | `providerDetails.jwkSetUri`                              |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.provider.[providerId].issuer-uri`                           | `providerDetails.issuerUri`                              |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.provider.[providerId].user-info-uri`                        | `providerDetails.userInfoEndpoint.uri`                   |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.provider.[providerId].user-info-authentication-method`      | `providerDetails.userInfoEndpoint.authenticationMethod`  |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+
| `spring.security.oauth2.client.provider.[providerId].user-name-attribute`                  | `providerDetails.userInfoEndpoint.userNameAttributeName` |
+--------------------------------------------------------------------------------------------+----------------------------------------------------------+

:::: tip
::: title
:::

您可以通过指定
`spring.security.oauth2.client.provider.[providerId].issuer-uri`
属性，利用 OpenID Connect 提供者的
[配置端点](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)
或授权服务器的
[元数据端点](https://tools.ietf.org/html/rfc8414#section-3)
发现来初始化配置 `ClientRegistration`。
::::

# CommonOAuth2Provider {#oauth2login-common-oauth2-provider}

`CommonOAuth2Provider`
为一些知名提供商预定义了一组默认客户端属性：Google、GitHub、Facebook 和
Okta。

例如，某个提供商的 `authorization-uri`、`token-uri` 和 `user-info-uri`
很少更改。 因此，提供默认值是有意义的，可以减少所需的配置量。

如前所述，当我们 [配置 Google
客户端](#oauth2login-sample-application-config)时，仅需提供 `client-id`
和 `client-secret` 属性即可。

以下列表展示了一个示例：

``` yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: google-client-id
            client-secret: google-client-secret
```

:::: tip
::: title
:::

由于 `registrationId`（`google`）与 `CommonOAuth2Provider` 中的 `GOOGLE`
枚举（不区分大小写）匹配，因此此处的客户端属性自动默认化工作无缝衔接。
::::

对于希望指定不同 `registrationId` 的情况（例如
`google-login`），您仍可通过配置 `provider`
属性来利用客户端属性的自动默认化。

以下列表展示了一个示例：

``` yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google-login: 
            provider: google    
            client-id: google-client-id
            client-secret: google-client-secret
```

- `registrationId` 被设置为 `google-login`。

- `provider` 属性被设置为 `google`，这将利用
  `CommonOAuth2Provider.GOOGLE.getBuilder()`
  中设定的客户端属性自动默认化。

# 配置自定义提供者属性 {#oauth2login-custom-provider-properties}

某些 OAuth 2.0
提供商支持多租户，导致每个租户（或子域）有不同的协议端点。

例如，注册于 Okta 的 OAuth
客户端会被分配到特定的子域，并拥有自己的协议端点。

在这种情况下，Spring Boot
提供了以下基础属性用于配置自定义提供者属性：`spring.security.oauth2.client.provider.[providerId]`。

以下列表展示了一个示例：

``` yaml
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            client-id: okta-client-id
            client-secret: okta-client-secret
        provider:
          okta: 
            authorization-uri: https://your-subdomain.oktapreview.com/oauth2/v1/authorize
            token-uri: https://your-subdomain.oktapreview.com/oauth2/v1/token
            user-info-uri: https://your-subdomain.oktapreview.com/oauth2/v1/userinfo
            user-name-attribute: sub
            jwk-set-uri: https://your-subdomain.oktapreview.com/oauth2/v1/keys
```

- 基础属性 (`spring.security.oauth2.client.provider.okta`)
  允许对协议端点位置进行自定义配置。

# 覆盖 Spring Boot 自动配置 {#oauth2login-override-boot-autoconfig}

支持 OAuth 客户端的 Spring Boot 自动配置类是
`OAuth2ClientAutoConfiguration`。

它执行以下任务：

- 注册一个由配置的 OAuth 客户端属性构成的 `ClientRegistrationRepository`
  `@Bean`。

- 注册一个 `SecurityFilterChain` `@Bean` 并通过
  `httpSecurity.oauth2Login()` 启用 OAuth 2.0 登录。

如果您需要根据特定需求覆盖自动配置，可以通过以下方式实现：

- [注册 ClientRegistrationRepository
  \@Bean](#oauth2login-register-clientregistrationrepository-bean)

- [注册 SecurityFilterChain
  \@Bean](#oauth2login-provide-securityfilterchain-bean)

- [完全覆盖自动配置](#oauth2login-completely-override-autoconfiguration)

## 注册 ClientRegistrationRepository \@Bean {#oauth2login-register-clientregistrationrepository-bean}

以下示例展示了如何注册 `ClientRegistrationRepository` `@Bean`：

::: informalexample

Java

:   ``` java
    @Configuration
    public class OAuth2LoginConfig {

        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
        }

        private ClientRegistration googleClientRegistration() {
            return ClientRegistration.withRegistrationId("google")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email", "address", "phone")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .clientName("Google")
                .build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    class OAuth2LoginConfig {
        @Bean
        fun clientRegistrationRepository(): ClientRegistrationRepository {
            return InMemoryClientRegistrationRepository(googleClientRegistration())
        }

        private fun googleClientRegistration(): ClientRegistration {
            return ClientRegistration.withRegistrationId("google")
                    .clientId("google-client-id")
                    .clientSecret("google-client-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope("openid", "profile", "email", "address", "phone")
                    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                    .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                    .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                    .userNameAttributeName(IdTokenClaimNames.SUB)
                    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                    .clientName("Google")
                    .build()
        }
    }
    ```
:::

## 注册 SecurityFilterChain \@Bean {#oauth2login-provide-securityfilterchain-bean}

以下示例展示了如何使用 `@EnableWebSecurity` 注册 `SecurityFilterChain`
`@Bean` 并通过 `httpSecurity.oauth2Login()` 启用 OAuth 2.0 登录：

:::: example
::: title
OAuth2 登录配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated()
                )
                .oauth2Login(withDefaults());
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    class OAuth2LoginSecurityConfig {

        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2Login { }
            }
            return http.build()
        }
    }
    ```
::::

## 完全覆盖自动配置 {#oauth2login-completely-override-autoconfiguration}

以下示例展示了如何通过注册 `ClientRegistrationRepository` `@Bean` 和
`SecurityFilterChain` `@Bean` 来完全覆盖自动配置。

:::: example
::: title
覆盖自动配置
:::

Java

:   ``` java
    @Configuration
    public class OAuth2LoginConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated()
                )
                .oauth2Login(withDefaults());
            return http.build();
        }

        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
        }

        private ClientRegistration googleClientRegistration() {
            return ClientRegistration.withRegistrationId("google")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email", "address", "phone")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .clientName("Google")
                .build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    class OAuth2LoginConfig {

        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2Login { }
            }
            return http.build()
        }

        @Bean
        fun clientRegistrationRepository(): ClientRegistrationRepository {
            return InMemoryClientRegistrationRepository(googleClientRegistration())
        }

        private fun googleClientRegistration(): ClientRegistration {
            return ClientRegistration.withRegistrationId("google")
                    .clientId("google-client-id")
                    .clientSecret("google-client-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope("openid", "profile", "email", "address", "phone")
                    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                    .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                    .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                    .userNameAttributeName(IdTokenClaimNames.SUB)
                    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                    .clientName("Google")
                    .build()
        }
    }
    ```
::::

# 不使用 Spring Boot 的 Java 配置 {#oauth2login-javaconfig-wo-boot}

如果您无法使用 Spring Boot，并希望配置 `CommonOAuth2Provider`
中的一个预定义提供者（例如 Google），请应用以下配置：

:::: example
::: title
OAuth2 登录配置
:::

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class OAuth2LoginConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated()
                )
                .oauth2Login(withDefaults());
            return http.build();
        }

        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
        }

        @Bean
        public OAuth2AuthorizedClientService authorizedClientService(
                ClientRegistrationRepository clientRegistrationRepository) {
            return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
        }

        @Bean
        public OAuth2AuthorizedClientRepository authorizedClientRepository(
                OAuth2AuthorizedClientService authorizedClientService) {
            return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
        }

        private ClientRegistration googleClientRegistration() {
            return CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    open class OAuth2LoginConfig {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2Login { }
            }
            return http.build()
        }

        @Bean
        open fun clientRegistrationRepository(): ClientRegistrationRepository {
            return InMemoryClientRegistrationRepository(googleClientRegistration())
        }

        @Bean
        open fun authorizedClientService(
            clientRegistrationRepository: ClientRegistrationRepository?
        ): OAuth2AuthorizedClientService {
            return InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository)
        }

        @Bean
        open fun authorizedClientRepository(
            authorizedClientService: OAuth2AuthorizedClientService?
        ): OAuth2AuthorizedClientRepository {
            return AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService)
        }

        private fun googleClientRegistration(): ClientRegistration {
            return CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .build()
        }
    }
    ```

Xml

:   ``` xml
    <http auto-config="true">
        <intercept-url pattern="/**" access="authenticated"/>
        <oauth2-login authorized-client-repository-ref="authorizedClientRepository"/>
    </http>

    <client-registrations>
        <client-registration registration-id="google"
                             client-id="google-client-id"
                             client-secret="google-client-secret"
                             provider-id="google"/>
    </client-registrations>

    <b:bean id="authorizedClientService"
            class="org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService"
            autowire="constructor"/>

    <b:bean id="authorizedClientRepository"
            class="org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository">
        <b:constructor-arg ref="authorizedClientService"/>
    </b:bean>
    ```
::::
