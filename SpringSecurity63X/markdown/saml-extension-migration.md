本文档提供了将 SAML 2.0 服务提供方（Service Provider）从 Spring Security
SAML Extensions 1.x 迁移到 Spring Security 的指导。由于 Spring Security
不提供身份提供方（Identity Provider）支持，因此本文档不涵盖对 Spring
Security SAML Extensions 身份提供方的迁移。

由于两种实现方式存在显著差异，本文档更侧重于介绍迁移模式，而非提供精确的一一对应的搜索替换步骤。

# 登录与登出 {#saml2-login-logout}

## 方法上的变更 {#_方法上的变更}

[Spring Security](https://github.com/spring-projects/spring-security)
在若干关键方面采用了与 [Spring Security SAML
Extensions](https://github.com/spring-projects/spring-security-saml)
不同的方法。

### 简化的启用方式 {#_简化的启用方式}

Spring Security SAML Extensions 通过在多个 Spring Security
过滤器链中手动按正确顺序添加一系列过滤器来实现服务提供方的支持。

而 Spring Security 的 SAML 2.0 服务提供方支持则通过 Spring Security DSL
方法进行启用： [`saml2Login`](servlet/saml2/login/index.xml)、
[`saml2Logout`](servlet/saml2/logout.xml) 和
[`saml2Metadata`](servlet/saml2/metadata.xml)。这些方法会自动选择需要添加的正确过滤器，并将其放置在过滤器链中的适当位置。

### 更强的封装性 {#_更强的封装性}

尽管 Spring Security 和 Spring Security SAML Extensions 都基于 OpenSAML
实现 SAML 支持，但扩展项目通过公共接口暴露了
OpenSAML，模糊了两个项目之间的界限，实质上强制依赖
OpenSAML，并使得升级到更高版本的 OpenSAML 变得更加复杂。

Spring Security 提供了更强的封装性：没有任何公共接口暴露 OpenSAML
组件；任何在其公共 API 中使用 OpenSAML 的类都会以 `OpenSaml`
作为前缀命名，以增强清晰度。

### 内建的多租户支持 {#_内建的多租户支持}

Spring Security SAML Extensions
提供了一些轻量级功能，允许声明多个身份提供方，并在登录时通过 `idp`
请求参数访问它们。这种方式在运行时动态更改配置方面存在限制，也无法支持依赖方与断言方之间的多对多关系。

Spring Security 将 SAML 2.0 多租户机制集成到了默认 URL
和基础组件中，形式为
`RelyingPartyRegistration`。该组件充当依赖方（Relying
Party）元数据和断言方（Asserting Party）元数据之间的桥梁，所有配对均可在
`RelyingPartyRegistrationRepository` 中查找。每个 URL
对应一个唯一的注册配对，用于检索。

无论是认证请求（AuthnRequests）、响应（Responses）、登出请求（LogoutRequests）、登出响应（LogoutResponses），还是实体描述符（EntityDescriptors），每个过滤器都基于
`RelyingPartyRegistrationRepository` 构建，因此天然支持多租户。

## 示例对照表 {#_示例对照表}

Spring Security 和 Spring Security SAML Extensions
均提供了服务提供方的配置示例：

+----------------------+----------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| 使用场景             | Spring Security                                                                                                                  | Spring Security SAML Extensions                                                        |
+======================+==================================================================================================================================+========================================================================================+
| 登录与登出           | [示例](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/saml2/login)                | [示例](https://github.com/jzheaux/spring-security-saml-migrate/tree/main/login-logout) |
+----------------------+----------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| 使用 SAML 扩展的 URL | [示例](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/saml2/custom-urls)          | \-                                                                                     |
| 登录                 |                                                                                                                                  |                                                                                        |
+----------------------+----------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| 元数据支持           | [示例](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/saml2/refreshable-metadata) | \-                                                                                     |
+----------------------+----------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+

你还可以在 [Spring Security SAML
Extensions](https://github.com/spring-projects/spring-security-saml/tree/main/sample)
的 GitHub 项目中查看综合示例。

:::: note
::: title
:::

Spring Security 不支持对 SAML 2.0 响应使用 HTTP-Redirect 绑定。 根据
SAML 规范，由于 URL 长度和签名限制，HTTP-Redirect 绑定不允许用于 SAML
响应。若尝试使用此绑定，可能导致意外错误。 请在配置身份提供方时使用
HTTP-POST 绑定。
::::

# 尚未迁移的功能 {#saml2-unported}

以下一些功能目前尚未迁移到 Spring Security，且暂时没有计划进行支持：

- SAML 2.0 响应对的 HTTP-Redirect 绑定

- Artifact 绑定支持
