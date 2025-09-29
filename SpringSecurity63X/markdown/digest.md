本节详细介绍 Spring Security 如何通过 `DigestAuthenticationFilter`
提供对 [摘要认证（Digest
Authentication）](https://tools.ietf.org/html/rfc2617) 的支持。

:::: warning
::: title
:::

在现代应用程序中不应使用摘要认证，因为它被认为不够安全。
最明显的问题是：你必须以明文、加密或 MD5 格式存储密码。
这些存储方式均被视为不安全。 相反，你应该使用单向自适应密码哈希算法（如
bCrypt、PBKDF2、SCrypt 等）来存储凭证，而摘要认证并不支持此类算法。
::::

摘要认证旨在解决 [基本认证（Basic
Authentication）](servlet/authentication/passwords/basic.xml#servlet-authentication-basic)
的许多弱点，尤其是确保凭据不会以明文形式在网络上传输。 许多
[浏览器支持摘要认证](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Digest#Browser_compatibility)。

HTTP 摘要认证的标准由 [RFC 2617](https://tools.ietf.org/html/rfc2617)
定义，该标准更新了早期由 [RFC 2069](https://tools.ietf.org/html/rfc2069)
规定的摘要认证版本。 大多数用户代理实现了 RFC 2617。Spring Security
的摘要认证支持兼容 RFC 2617 所规定的 "auth"
保护质量（`qop`），同时也向后兼容 RFC 2069。 如果你需要在未加密的
HTTP（无 TLS 或
HTTPS）环境下使用认证，并希望最大化认证过程的安全性，那么摘要认证曾被视为更具吸引力的选择。
然而，现在每个人都应该使用 [HTTPS](features/exploits/http.xml#http)。

摘要认证的核心是一个
"nonce"（一次性随机值），这是由服务器生成的一个值。Spring Security 中的
nonce 采用如下格式：

:::: formalpara
::: title
Digest 语法
:::

``` txt
base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
expirationTime:   nonce 过期的时间戳（单位为毫秒）
key:              用于防止 nonce 被篡改的私钥
```
::::

你需要确保已正确
[配置](features/authentication/password-storage.xml#authentication-password-storage-configuration)
不安全的明文
[密码存储](features/authentication/password-storage.xml#authentication-password-storage)，使用
`NoOpPasswordEncoder`。 （参见 Javadoc 中的
{security-api-url}org/springframework/security/crypto/password/NoOpPasswordEncoder.html\[`NoOpPasswordEncoder`\]
类）。以下示例展示了如何通过 Java 配置启用摘要认证：

:::: example
::: title
Digest 认证配置
:::

Java

:   ``` java
    @Autowired
    UserDetailsService userDetailsService;

    DigestAuthenticationEntryPoint authenticationEntryPoint() {
        DigestAuthenticationEntryPoint result = new DigestAuthenticationEntryPoint();
        result.setRealmName("My App Realm");
        result.setKey("3028472b-da34-4501-bfd8-a355c42bdf92");
        return result;
    }

    DigestAuthenticationFilter digestAuthenticationFilter() {
        DigestAuthenticationFilter result = new DigestAuthenticationFilter();
        result.setUserDetailsService(userDetailsService);
        result.setAuthenticationEntryPoint(authenticationEntryPoint());
        return result;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ...
            .exceptionHandling(e -> e.authenticationEntryPoint(authenticationEntryPoint()))
            .addFilter(digestAuthenticationFilter());
        return http.build();
    }
    ```

XML

:   ``` xml
    <b:bean id="digestFilter"
            class="org.springframework.security.web.authentication.www.DigestAuthenticationFilter"
        p:userDetailsService-ref="jdbcDaoImpl"
        p:authenticationEntryPoint-ref="digestEntryPoint"
    />

    <b:bean id="digestEntryPoint"
            class="org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint"
        p:realmName="My App Realm"
        p:key="3028472b-da34-4501-bfd8-a355c42bdf92"
    />

    <http>
        <!-- ... -->
        <custom-filter ref="userFilter" position="DIGEST_AUTH_FILTER"/>
    </http>
    ```
::::
