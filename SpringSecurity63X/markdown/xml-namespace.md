自 Spring 框架 2.0 版本起，就支持了命名空间配置。它允许你在传统的 Spring
Bean 应用上下文语法基础上，使用额外 XML Schema 的元素进行补充。你可以在
Spring
[参考文档](https://docs.spring.io/spring/docs/current/spring-framework-reference/htmlsingle/)
中找到更多相关信息。你可以使用命名空间元素来更简洁地配置单个
Bean，或者更强大地定义一种更贴近问题域的替代配置语法，从而对用户隐藏底层实现的复杂性。一个简单的元素可以隐藏多个
Bean 和处理步骤被添加到应用上下文的事实。例如，在应用上下文中添加来自
`security` 命名空间的以下元素，将启动一个嵌入式 LDAP
服务器，供应用程序测试使用：

``` xml
<security:ldap-server />
```

这比手动配置等效的 Apache Directory Server Bean
要简单得多。`ldap-server`
元素通过属性支持最常见的配置需求，用户无需关心需要创建哪些 Bean 或 Bean
属性名称是什么。你可以在 [LDAP
认证](servlet/authentication/passwords/ldap.xml#servlet-authentication-ldap)
章节中了解有关 `ldap-server`
元素使用的更多信息。在编辑应用上下文文件时，一个好的 XML
编辑器应能提供可用属性和元素的信息。我们建议尝试使用 [Spring Tool
Suite](https://spring.io/tools/sts)，因为它具有针对标准 Spring
命名空间的特殊功能。

要在你的应用上下文中使用 `security` 命名空间，请将
`spring-security-config` jar
包添加到类路径中。然后，你只需在应用上下文文件中添加 Schema 声明即可：

``` xml
<beans xmlns="http://www.springframework.org/schema/beans"
xmlns:security="http://www.springframework.org/schema/security"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://www.springframework.org/schema/beans
        https://www.springframework.org/schema/beans/spring-beans-3.0.xsd
        http://www.springframework.org/schema/security
        https://www.springframework.org/schema/security/spring-security.xsd">
    ...
</beans>
```

在许多示例（以及示例应用程序）中，我们通常使用 `security`（而不是
`beans`）作为默认命名空间，这意味着我们可以省略所有安全命名空间元素的前缀，使内容更易读。如果你将应用上下文划分为多个独立文件，并且大部分安全配置集中在其中一个文件中，你也可能希望这样做。此时，你的安全应用上下文文件开头如下所示：

``` xml
<beans:beans xmlns="http://www.springframework.org/schema/security"
xmlns:beans="http://www.springframework.org/schema/beans"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://www.springframework.org/schema/beans
        https://www.springframework.org/schema/beans/spring-beans-3.0.xsd
        http://www.springframework.org/schema/security
        https://www.springframework.org/schema/security/spring-security.xsd">
    ...
</beans:beans>
```

从现在起，本章假设使用这种语法。

# 命名空间设计 {#_命名空间设计}

该命名空间的设计旨在涵盖框架最常用的功能，并提供一种简化且简洁的语法，以便在应用中启用这些功能。设计基于框架中的大规模依赖关系，可划分为以下几个方面：

- *Web/HTTP 安全* 是最复杂的部分。它设置用于应用框架认证机制、保护
  URL、渲染登录和错误页面等的过滤器及相关服务 Bean。

- *业务对象（方法）安全* 定义了保护服务层的选项。

- *AuthenticationManager* 处理来自框架其他部分的认证请求。

- *AccessDecisionManager* 为 Web
  和方法安全提供访问决策。会自动注册一个默认实例，但你也可以选择使用自定义的
  AccessDecisionManager，通过常规的 Spring Bean 语法声明。

- *AuthenticationProvider*
  实例提供了认证管理器用来验证用户身份的机制。命名空间支持多种标准选项，并提供了一种方式来添加使用传统语法声明的自定义
  Bean。

- *UserDetailsService* 与认证提供者密切相关，但也经常被其他 Bean 所需。

我们将在接下来的章节中了解如何配置这些组件。

# 开始使用安全命名空间配置 {#ns-getting-started}

本节介绍如何构建命名空间配置以使用框架的一些主要功能。我们假设你最初希望尽快上手，并为现有的
Web
应用程序快速添加认证支持和访问控制，同时包含一些测试登录账户。然后，我们将探讨如何切换为对数据库或其他安全存储库进行认证。在后面的章节中，我们将介绍更高级的命名空间配置选项。

## web.xml 配置 {#ns-web-xml}

首先，你需要在 `web.xml` 文件中添加以下过滤器声明：

``` xml
<filter>
<filter-name>springSecurityFilterChain</filter-name>
<filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
<filter-name>springSecurityFilterChain</filter-name>
<url-pattern>/*</url-pattern>
</filter-mapping>
```

`DelegatingFilterProxy` 是 Spring
框架中的一个类，它会代理由应用上下文中的 Spring Bean
定义的过滤器实现。在这种情况下，Bean 名称为
`springSecurityFilterChain`，这是命名空间创建的一个内部基础设施
Bean，用于处理 Web 安全。请注意，你不应自行使用此 Bean 名称。一旦将此
Bean 添加到 `web.xml` 中，就可以开始编辑应用上下文文件了。Web 安全服务由
`<http>` 元素配置。

## 最小化的 \<http\> 配置 {#ns-minimal}

要启用 Web 安全，你需要以下配置：

``` xml
<http>
<intercept-url pattern="/**" access="hasRole('USER')" />
<form-login />
<logout />
</http>
```

上述配置表示我们希望：

- 应用程序内的所有 URL 都受到保护，访问它们需要具备 `ROLE_USER` 角色；

- 使用用户名和密码的表单登录到应用程序；

- 注册一个注销 URL，以便我们可以退出应用程序。

`<http>` 元素是所有与 Web 相关的命名空间功能的父元素。`<intercept-url>`
元素定义了一个 `pattern`，该模式使用 Ant 路径语法匹配传入请求的
URL。有关实际匹配方式的更多详细信息，请参阅
[`HttpFirewall`](servlet/exploits/firewall.xml#servlet-httpfirewall)
章节。你也可以使用正则表达式匹配作为替代方式（详见命名空间附录）。`access`
属性定义了符合给定模式的请求所需的访问权限。在默认配置下，这通常是一个以逗号分隔的角色列表，用户必须拥有其中至少一个角色才能允许请求。`ROLE_`
前缀是一个标记，表示应直接与用户的权限进行比较。换句话说，应使用普通的基于角色的检查。Spring
Security
中的访问控制不仅限于简单的角色（因此使用前缀来区分不同类型的安全属性）。稍后我们会看到其解释方式如何变化。`access`
属性中逗号分隔值的解释取决于所使用的
[`AccessDecisionManager`](#ns-access-manager) 实现。自 Spring Security
3.0 起，你还可以在该属性中填充 [EL
表达式](servlet/authorization/authorize-http-requests.xml#authorization-expressions)。

:::: note
::: title
:::

你可以使用多个 `<intercept-url>` 元素为不同 URL
集合定义不同的访问要求，但它们按列出顺序进行评估，并使用第一个匹配项。因此，你必须将最具体的匹配项放在顶部。你还可以添加
`method` 属性，将匹配限制为特定的 HTTP 方法（如 `GET`、`POST`、`PUT`
等）。
::::

要添加用户，可以直接在命名空间中定义一组测试数据：

``` xml
<authentication-manager>
<authentication-provider>
    <user-service>
    <!-- 密码以 {noop} 开头，表示 DelegatingPasswordEncoder 应使用 NoOpPasswordEncoder。
    这种方式不适用于生产环境，但在示例中更容易阅读。
    正常情况下，密码应使用 BCrypt 进行哈希 -->
    <user name="jimi" password="{noop}jimispassword" authorities="ROLE_USER, ROLE_ADMIN" />
    <user name="bob" password="{noop}bobspassword" authorities="ROLE_USER" />
    </user-service>
</authentication-provider>
</authentication-manager>
```

以上列表展示了一种安全存储相同密码的示例。密码以 `{bcrypt}`
开头，用于指示 `DelegatingPasswordEncoder`（支持任何已配置的
`PasswordEncoder` 匹配），密码使用 BCrypt 进行哈希：

``` xml
<authentication-manager>
<authentication-provider>
    <user-service>
    <user name="jimi" password="{bcrypt}$2a$10$ddEWZUl8aU0GdZPPpy7wbu82dvEw/pBpbRvDQRqA41y6mK1CoH00m"
            authorities="ROLE_USER, ROLE_ADMIN" />
    <user name="bob" password="{bcrypt}$2a$10$/elFpMBnAYYig6KRR5bvOOYeZr1ie1hSogJryg9qDlhza4oCw1Qka"
            authorities="ROLE_USER" />
    <user name="jimi" password="{noop}jimispassword" authorities="ROLE_USER, ROLE_ADMIN" />
    <user name="bob" password="{noop}bobspassword" authorities="ROLE_USER" />
    </user-service>
</authentication-provider>
</authentication-manager>
```

:::: sidebar
::: title
:::

`<http>` 元素负责创建 `FilterChainProxy` 及其使用的过滤器
Bean。过去常见的问题，如过滤器顺序错误，现在不再是问题，因为过滤器的位置是预定义的。

`<authentication-provider>` 元素创建一个 `DaoAuthenticationProvider`
Bean，而 `<user-service>` 元素创建一个 `InMemoryDaoImpl`。所有
`authentication-provider` 元素都必须是 `<authentication-manager>`
元素的子元素，后者创建 `ProviderManager` 并向其注册认证提供者。你可以在
[命名空间附录](servlet/appendix/namespace/index.xml#appendix-namespace)
中找到更多关于所创建 Bean
的详细信息。如果你想开始理解框架中重要的类及其用途，特别是当你想以后进行自定义时，应交叉核对此附录。
::::

上述配置定义了两个用户、他们的密码以及他们在应用程序中的角色（用于访问控制）。你还可以通过设置
`user-service` 元素的 `properties`
属性，从标准属性文件加载用户信息。有关文件格式的更多细节，请参见
[内存中认证](servlet/authentication/passwords/in-memory.xml#servlet-authentication-inmemory)
章节。使用 `<authentication-provider>`
元素意味着用户信息将被认证管理器用于处理认证请求。你可以有多个
`<authentication-provider>` 元素来定义不同的认证源，每个源将依次被查询。

此时，你应该能够启动你的应用程序，并且会被要求登录才能继续。试试看，或尝试实验项目附带的
"tutorial" 示例应用程序。

### 设置默认登录后跳转目标 {#ns-form-target}

如果表单登录不是由于尝试访问受保护资源而触发的，则 `default-target-url`
选项将起作用。这是用户成功登录后跳转的 URL，默认为 `/`。你还可以通过将
`always-use-default-target` 属性设置为 `true` 来配置，使用户 *总是*
跳转到此页面（无论登录是"按需"还是用户显式选择登录）。当你的应用程序始终要求用户从"主页"开始时，这非常有用，例如：

``` xml
<http pattern="/login.htm*" security="none"/>
<http use-expressions="false">
<intercept-url pattern='/**' access='ROLE_USER' />
<form-login login-page='/login.htm' default-target-url='/home.htm'
        always-use-default-target='true' />
</http>
```

为了对跳转目标进行更精细的控制，你可以使用
`authentication-success-handler-ref` 属性替代
`default-target-url`。引用的 Bean 应为 `AuthenticationSuccessHandler`
的实例。

# 高级 Web 功能 {#ns-web-advanced}

本节涵盖超出基础功能的各种特性。

## 添加自定义过滤器 {#ns-custom-filters}

如果你之前使用过 Spring
Security，你会知道该框架维护一个过滤器链来应用其服务。你可能希望在特定位置向该链中添加自己的过滤器，或使用某个目前尚无命名空间配置选项的
Spring Security 过滤器（例如 CAS 过滤器）。// FIXME: 是否仍然没有 CAS
过滤器？ 另外，你可能希望使用标准命名空间过滤器的自定义版本，比如
`UsernamePasswordAuthenticationFilter`（由 `<form-login>`
元素创建），以利用显式使用 Bean
时可用的额外配置选项。在命名空间配置下，如何实现这一点？毕竟过滤器链并未直接暴露。

当你使用命名空间时，过滤器的顺序总是严格强制执行的。在创建应用上下文时，命名空间处理代码会对过滤器
Bean 进行排序，每个标准 Spring Security
过滤器在命名空间中都有别名和固定位置。

:::: note
::: title
:::

在以前的版本中，排序发生在过滤器实例创建之后，即在应用上下文的后处理阶段完成。而在
3.0+ 版本中，排序现在是在 Bean
元数据级别完成的，早于类实例化之前。这对如何将自定义过滤器添加到链中有影响：整个过滤器列表必须在解析
`<http>` 元素期间就被知晓，因此 3.0 版本中的语法略有变化。
::::

过滤器、别名以及创建这些过滤器的命名空间元素或属性按其在过滤器链中的出现顺序列于下表中：

+------------------------------+--------------------------------------------+------------------------------------------+
| 别名                         | 过滤器类                                   | 创建该过滤器的命名空间元素或属性         |
+==============================+============================================+==========================================+
| DISABLE_ENCODE_URL_FILTER    | `DisableEncodeUrlFilter`                   | `http@disable-url-rewriting`             |
+------------------------------+--------------------------------------------+------------------------------------------+
| FORCE_EAGER_SESSION_FILTER   | `ForceEagerSessionCreationFilter`          | `http@create-session="ALWAYS"`           |
+------------------------------+--------------------------------------------+------------------------------------------+
| CHANNEL_FILTER               | `ChannelProcessingFilter`                  | `http/intercept-url@requires-channel`    |
+------------------------------+--------------------------------------------+------------------------------------------+
| SECURITY_CONTEXT_FILTER      | `SecurityContextPersistenceFilter`         | `http`                                   |
+------------------------------+--------------------------------------------+------------------------------------------+
| CONCURRENT_SESSION_FILTER    | `ConcurrentSessionFilter`                  | `session-management/concurrency-control` |
+------------------------------+--------------------------------------------+------------------------------------------+
| HEADERS_FILTER               | `HeaderWriterFilter`                       | `http/headers`                           |
+------------------------------+--------------------------------------------+------------------------------------------+
| CSRF_FILTER                  | `CsrfFilter`                               | `http/csrf`                              |
+------------------------------+--------------------------------------------+------------------------------------------+
| LOGOUT_FILTER                | `LogoutFilter`                             | `http/logout`                            |
+------------------------------+--------------------------------------------+------------------------------------------+
| X509_FILTER                  | `X509AuthenticationFilter`                 | `http/x509`                              |
+------------------------------+--------------------------------------------+------------------------------------------+
| PRE_AUTH_FILTER              | `AbstractPreAuthenticatedProcessingFilter` | N/A                                      |
|                              | 子类                                       |                                          |
+------------------------------+--------------------------------------------+------------------------------------------+
| CAS_FILTER                   | `CasAuthenticationFilter`                  | N/A                                      |
+------------------------------+--------------------------------------------+------------------------------------------+
| FORM_LOGIN_FILTER            | `UsernamePasswordAuthenticationFilter`     | `http/form-login`                        |
+------------------------------+--------------------------------------------+------------------------------------------+
| BASIC_AUTH_FILTER            | `BasicAuthenticationFilter`                | `http/http-basic`                        |
+------------------------------+--------------------------------------------+------------------------------------------+
| SERVLET_API_SUPPORT_FILTER   | `SecurityContextHolderAwareRequestFilter`  | `http/@servlet-api-provision`            |
+------------------------------+--------------------------------------------+------------------------------------------+
| JAAS_API_SUPPORT_FILTER      | `JaasApiIntegrationFilter`                 | `http/@jaas-api-provision`               |
+------------------------------+--------------------------------------------+------------------------------------------+
| REMEMBER_ME_FILTER           | `RememberMeAuthenticationFilter`           | `http/remember-me`                       |
+------------------------------+--------------------------------------------+------------------------------------------+
| ANONYMOUS_FILTER             | `AnonymousAuthenticationFilter`            | `http/anonymous`                         |
+------------------------------+--------------------------------------------+------------------------------------------+
| SESSION_MANAGEMENT_FILTER    | `SessionManagementFilter`                  | `session-management`                     |
+------------------------------+--------------------------------------------+------------------------------------------+
| EXCEPTION_TRANSLATION_FILTER | `ExceptionTranslationFilter`               | `http`                                   |
+------------------------------+--------------------------------------------+------------------------------------------+
| FILTER_SECURITY_INTERCEPTOR  | `FilterSecurityInterceptor`                | `http`                                   |
+------------------------------+--------------------------------------------+------------------------------------------+
| SWITCH_USER_FILTER           | `SwitchUserFilter`                         | N/A                                      |
+------------------------------+--------------------------------------------+------------------------------------------+

: 标准过滤器别名及顺序 {#filter-stack}

你可以使用 `custom-filter`
元素并指定上述名称之一，将自定义过滤器添加到过滤器链中的指定位置：

``` xml
<http>
<custom-filter position="FORM_LOGIN_FILTER" ref="myFilter" />
</http>

<beans:bean id="myFilter" class="com.mycompany.MySpecialAuthenticationFilter"/>
```

你也可以使用 `after` 或 `before`
属性，让你的过滤器插入到另一个过滤器之前或之后。使用 `position` 属性配合
`FIRST` 和
`LAST`，可以分别表示你想让过滤器出现在整个链的最前面或最后面。

:::: tip
::: title
避免过滤器位置冲突
:::

如果你插入的自定义过滤器可能占据命名空间创建的标准过滤器的相同位置，则不应误包含命名空间版本的过滤器。请移除那些创建了你想要替换功能的过滤器的元素。

注意，你不能替换由 `<http>`
元素本身创建的过滤器：`SecurityContextPersistenceFilter`、`ExceptionTranslationFilter`
或 `FilterSecurityInterceptor`。默认情况下，会添加一个
`AnonymousAuthenticationFilter`，除非你禁用了
[会话固定保护](servlet/authentication/session-management.xml#ns-session-fixation)，否则还会向过滤器链中添加一个
`SessionManagementFilter`。
::::

如果你替换了需要认证入口点的命名空间过滤器（即认证过程由未认证用户尝试访问受保护资源触发），那么你也需要添加一个自定义的入口点
Bean。

# 方法安全 {#ns-method-security}

自 2.0 版本以来，Spring Security
对服务层方法的安全性提供了强大的支持。它支持 JSR-250
注解安全以及框架原有的 `@Secured` 注解。自 3.0 版本起，你还可以使用
[基于表达式的注解](servlet/authorization/method-security.xml#authorizing-with-annotations)。你可以通过使用
`intercept-methods` 元素修饰 Bean 声明来为单个 Bean
添加安全控制，也可以使用 AspectJ 风格的切点在整个服务层中保护多个 Bean。

# 默认的 AccessDecisionManager {#ns-access-manager}

本节假设你对 Spring Security
内部访问控制架构有一定了解。如果不了解，可以跳过本节，稍后再回来阅读，因为此部分内容仅适用于需要自定义以使用超出简单基于角色安全的人群。

当你使用命名空间配置时，系统会自动为你注册一个默认的
`AccessDecisionManager` 实例，并根据你在 `intercept-url` 和
`protect-pointcut`
声明（以及注解，如果你使用注解保护方法的话）中指定的访问属性，用于方法调用和
Web URL 访问的访问决策。

默认策略是使用带有 `RoleVoter` 和 `AuthenticatedVoter` 的
`AffirmativeBased` `AccessDecisionManager`。你可以在
[授权](servlet/authorization/architecture.xml#authz-arch)
章节中了解更多相关内容。

## 自定义 AccessDecisionManager {#ns-custom-access-mgr}

如果你需要使用更复杂的访问控制策略，可以分别为方法安全和 Web
安全设置替代方案。

对于方法安全，你可以在 `global-method-security` 上设置
`access-decision-manager-ref` 属性，将其指向应用上下文中适当的
`AccessDecisionManager` Bean 的 `id`：

``` xml
<global-method-security access-decision-manager-ref="myAccessDecisionManagerBean">
...
</global-method-security>
```

Web 安全的语法相同，但该属性位于 `http` 元素上：

``` xml
<http access-decision-manager-ref="myAccessDecisionManagerBean">
...
</http>
```
