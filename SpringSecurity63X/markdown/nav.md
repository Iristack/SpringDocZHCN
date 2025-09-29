- [概述](index.xml)

- [前置条件](prerequisites.xml)

- [社区](community.xml)

- [新特性](whats-new.xml)

- [准备升级到 7.0 版本](migration-7/index.xml)

  - [配置](migration-7/configuration.xml)

  - [LDAP](migration-7/ldap.xml)

- [迁移到 6.2 版本](migration/index.xml)

  - [授权变更](migration/authorization.xml)

- [获取 Spring Security](getting-spring-security.xml)

- [功能特性](features/index.xml)

  - [认证](features/authentication/index.xml)

    - [密码存储](features/authentication/password-storage.xml)

  - [授权](features/authorization/index.xml)

  - [防止安全漏洞](features/exploits/index.xml)

    - [CSRF 防护](features/exploits/csrf.xml)

    - [HTTP 头部](features/exploits/headers.xml)

    - [HTTP 请求](features/exploits/http.xml)

  - [集成](features/integrations/index.xml)

    - [加密](features/integrations/cryptography.xml)

    - [Spring Data](features/integrations/data.xml)

    - [Java 并发 API](features/integrations/concurrency.xml)

    - [Jackson](features/integrations/jackson.xml)

    - [本地化](features/integrations/localization.xml)

- [项目模块](modules.xml)

- [示例](samples.xml)

- [Servlet 应用](servlet/index.xml)

  - [快速入门](servlet/getting-started.xml)

  - [架构](servlet/architecture.xml)

  - [认证](servlet/authentication/index.xml)

    - [认证架构](servlet/authentication/architecture.xml)

    - [用户名/密码](servlet/authentication/passwords/index.xml)

      - [读取用户名/密码](servlet/authentication/passwords/input.xml)

        - [表单登录](servlet/authentication/passwords/form.xml)

        - [HTTP Basic](servlet/authentication/passwords/basic.xml)

        - [HTTP Digest](servlet/authentication/passwords/digest.xml)

      - **\***\*
        [密码存储](servlet/authentication/passwords/storage.xml)

        - [内存存储](servlet/authentication/passwords/in-memory.xml)

        - [JDBC 存储](servlet/authentication/passwords/jdbc.xml)

        - [UserDetails](servlet/authentication/passwords/user-details.xml)

        - [CredentialsContainer](servlet/authentication/passwords/credentials-container.xml)

        - [UserDetailsService](servlet/authentication/passwords/user-details-service.xml)

        - [PasswordEncoder](servlet/authentication/passwords/password-encoder.xml)

        - [DaoAuthenticationProvider](servlet/authentication/passwords/dao-authentication-provider.xml)

        - [LDAP](servlet/authentication/passwords/ldap.xml)

    - [持久化](servlet/authentication/persistence.xml)

    - [会话管理](servlet/authentication/session-management.xml)

    - [记住我](servlet/authentication/rememberme.xml)

    - [匿名访问](servlet/authentication/anonymous.xml)

    - [预认证](servlet/authentication/preauth.xml)

    - [JAAS](servlet/authentication/jaas.xml)

    - [CAS](servlet/authentication/cas.xml)

    - [X509](servlet/authentication/x509.xml)

    - [Run-As](servlet/authentication/runas.xml)

    - [注销](servlet/authentication/logout.xml)

    - [认证事件](servlet/authentication/events.xml)

  - [授权](servlet/authorization/index.xml)

    - [授权架构](servlet/authorization/architecture.xml)

    - [HTTP 请求授权](servlet/authorization/authorize-http-requests.xml)

    - [方法级安全](servlet/authorization/method-security.xml)

    - [领域对象安全 ACLs](servlet/authorization/acls.xml)

    - [授权事件](servlet/authorization/events.xml)

  - [OAuth2](servlet/oauth2/index.xml)

    - [OAuth2 登录](servlet/oauth2/login/index.xml)

      - [核心配置](servlet/oauth2/login/core.xml)

      - [高级配置](servlet/oauth2/login/advanced.xml)

      - [OIDC 注销](servlet/oauth2/login/logout.xml)

    - [OAuth2 客户端](servlet/oauth2/client/index.xml)

      - [核心接口与类](servlet/oauth2/client/core.xml)

      - [OAuth2
        授权模式](servlet/oauth2/client/authorization-grants.xml)

      - [OAuth2
        客户端认证](servlet/oauth2/client/client-authentication.xml)

      - [OAuth2
        已授权客户端](servlet/oauth2/client/authorized-clients.xml)

    - [OAuth2 资源服务器](servlet/oauth2/resource-server/index.xml)

      - [JWT](servlet/oauth2/resource-server/jwt.xml)

      - [不透明令牌](servlet/oauth2/resource-server/opaque-token.xml)

      - [多租户](servlet/oauth2/resource-server/multitenancy.xml)

      - [Bearer Token](servlet/oauth2/resource-server/bearer-tokens.xml)

  - [SAML2](servlet/saml2/index.xml)

    - [SAML2 登录](servlet/saml2/login/index.xml)

      - [SAML2 登录概述](servlet/saml2/login/overview.xml)

      - [SAML2
        认证请求](servlet/saml2/login/authentication-requests.xml)

      - [SAML2 认证响应](servlet/saml2/login/authentication.xml)

    - [SAML2 注销](servlet/saml2/logout.xml)

    - [SAML2 元数据](servlet/saml2/metadata.xml)

    - [从 Spring Security SAML
      扩展迁移](servlet/saml2/saml-extension-migration.xml)

  - [防止安全漏洞](servlet/exploits/index.xml)

    - [CSRF](servlet/exploits/csrf.xml)

    - [HTTP 头部](servlet/exploits/headers.xml)

    - [HTTP 请求](servlet/exploits/http.xml)

    - [防火墙](servlet/exploits/firewall.xml)

  - [集成](servlet/integrations/index.xml)

    - [并发支持](servlet/integrations/concurrency.xml)

    - [Jackson](servlet/integrations/jackson.xml)

    - [本地化](servlet/integrations/localization.xml)

    - [Servlet API](servlet/integrations/servlet-api.xml)

    - [Spring Data](servlet/integrations/data.xml)

    - [Spring MVC](servlet/integrations/mvc.xml)

    - [WebSocket](servlet/integrations/websocket.xml)

    - [Spring 的 CORS 支持](servlet/integrations/cors.xml)

    - [JSP 标签库](servlet/integrations/jsp-taglibs.xml)

    - [可观测性](servlet/integrations/observability.xml)

  - 配置

    - [Java 配置](servlet/configuration/java.xml)

    - [Kotlin 配置](servlet/configuration/kotlin.xml)

    - [命名空间配置](servlet/configuration/xml-namespace.xml)

  - [测试](servlet/test/index.xml)

    - [方法安全测试](servlet/test/method.xml)

    - [MockMvc 支持](servlet/test/mockmvc/index.xml)

    - [MockMvc 设置](servlet/test/mockmvc/setup.xml)

    - [安全
      RequestPostProcessors](servlet/test/mockmvc/request-post-processors.xml)

      - [模拟用户](servlet/test/mockmvc/authentication.xml)

      - [模拟 CSRF](servlet/test/mockmvc/csrf.xml)

      - [模拟表单登录](servlet/test/mockmvc/form-login.xml)

      - [模拟 HTTP Basic](servlet/test/mockmvc/http-basic.xml)

      - [模拟 OAuth2](servlet/test/mockmvc/oauth2.xml)

      - [模拟注销](servlet/test/mockmvc/logout.xml)

    - [安全 RequestBuilders](servlet/test/mockmvc/request-builders.xml)

    - [安全 ResultMatchers](servlet/test/mockmvc/result-matchers.xml)

    - [安全 ResultHandlers](servlet/test/mockmvc/result-handlers.xml)

  - [附录](servlet/appendix/index.xml)

    - [数据库模式](servlet/appendix/database-schema.xml)

    - [XML 命名空间](servlet/appendix/namespace/index.xml)

      - [认证服务](servlet/appendix/namespace/authentication-manager.xml)

      - [Web 安全](servlet/appendix/namespace/http.xml)

      - [方法安全](servlet/appendix/namespace/method-security.xml)

      - [LDAP 安全](servlet/appendix/namespace/ldap.xml)

      - [WebSocket 安全](servlet/appendix/namespace/websocket.xml)

    - [代理服务器配置](servlet/appendix/proxy-server.xml)

    - [常见问题](servlet/appendix/faq.xml)

- [响应式应用](reactive/index.xml)

  - [快速入门](reactive/getting-started.xml)

  - [认证](reactive/authentication/index.xml)

    - [X.509 认证](reactive/authentication/x509.xml)

    - [注销](reactive/authentication/logout.xml)

    - 会话管理

      - [并发会话控制](reactive/authentication/concurrent-sessions-control.xml)

  - 授权

    - [HTTP
      请求授权](reactive/authorization/authorize-http-requests.xml)

    - [启用响应式方法安全
      EnableReactiveMethodSecurity](reactive/authorization/method.xml)

  - [OAuth2](reactive/oauth2/index.xml)

    - [OAuth2 登录](reactive/oauth2/login/index.xml)

      - [核心配置](reactive/oauth2/login/core.xml)

      - [高级配置](reactive/oauth2/login/advanced.xml)

      - [OIDC 注销](reactive/oauth2/login/logout.xml)

    - [OAuth2 客户端](reactive/oauth2/client/index.xml)

      - [核心接口与类](reactive/oauth2/client/core.xml)

      - [OAuth2
        授权模式](reactive/oauth2/client/authorization-grants.xml)

      - [OAuth2
        客户端认证](reactive/oauth2/client/client-authentication.xml)

      - [OAuth2
        已授权客户端](reactive/oauth2/client/authorized-clients.xml)

    - [OAuth2 资源服务器](reactive/oauth2/resource-server/index.xml)

      - [JWT](reactive/oauth2/resource-server/jwt.xml)

      - [不透明令牌](reactive/oauth2/resource-server/opaque-token.xml)

      - [多租户](reactive/oauth2/resource-server/multitenancy.xml)

      - [Bearer
        Token](reactive/oauth2/resource-server/bearer-tokens.xml)

  - [防止安全漏洞](reactive/exploits/index.xml)

    - [CSRF](reactive/exploits/csrf.xml)

    - [头部](reactive/exploits/headers.xml)

    - [HTTP 请求](reactive/exploits/http.xml)

    - [防火墙](reactive/exploits/firewall.xml)

  - 集成

    - [CORS](reactive/integrations/cors.xml)

    - [RSocket](reactive/integrations/rsocket.xml)

    - [可观测性](reactive/integrations/observability.xml)

  - [测试](reactive/test/index.xml)

    - [测试方法安全](reactive/test/method.xml)

    - [测试 Web 安全](reactive/test/web/index.xml)

      - [WebTestClient 设置](reactive/test/web/setup.xml)

      - [测试认证](reactive/test/web/authentication.xml)

      - [测试 CSRF](reactive/test/web/csrf.xml)

      - [测试 OAuth 2.0](reactive/test/web/oauth2.xml)

  - [WebFlux 安全](reactive/configuration/webflux.xml)

- [GraalVM 原生镜像支持](native-image/index.xml)

  - [方法安全](native-image/method-security.xml)
