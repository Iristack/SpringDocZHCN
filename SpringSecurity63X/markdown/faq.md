本常见问题解答包含以下部分：

- [一般性问题](#appendix-faq-general-questions)

- [常见问题](#appendix-faq-common-problems)

- [Spring Security 架构问题](#appendix-faq-architecture)

- [常见的"如何做"问题](#appendix-faq-howto)

# 一般性问题 {#appendix-faq-general-questions}

本常见问题解答回答了以下一般性问题：

- [Spring Security
  能否满足我应用的所有安全需求？](#appendix-faq-other-concerns)

- [为什么不使用 web.xml 安全配置？](#appendix-faq-web-xml)

- [需要哪些 Java 和 Spring Framework 版本？](#appendix-faq-requirements)

- [我有一个复杂的场景。可能是什么问题？](#appendix-faq-start-simple)

## Spring Security 能否满足我应用的所有安全需求？ {#appendix-faq-other-concerns}

Spring Security
为您的身份验证和授权需求提供了一个灵活的框架，但构建一个安全的应用程序还需要考虑许多其他方面，这些超出了其范围。
Web
应用容易受到各种攻击，您应该熟悉这些攻击，最好在开始开发之前就了解它们，以便从一开始就将安全性纳入设计和编码中。
请查看 [OWASP 网站](https://www.owasp.org/)，了解 Web
应用开发者面临的主要问题以及您可以使用的防御措施。

## 为什么不使用 web.xml 安全配置？ {#appendix-faq-web-xml}

假设您正在基于 Spring 开发一个企业级应用。
通常需要解决四个安全问题：认证、Web
请求安全、服务层安全（实现业务逻辑的方法）和领域对象实例安全（不同的领域对象可能有不同的权限）。考虑到这些典型需求，我们有以下几点考虑：

- *认证*: Servlet 规范提供了认证方法。
  然而，您需要配置容器来执行认证，这通常涉及编辑容器特定的 "realm"
  设置。 这会导致配置不可移植。此外，如果您需要编写 Java
  类来实现容器的认证接口，那么可移植性会更差。 使用 Spring
  Security，您可以实现完全的可移植性------甚至到 WAR 包级别。
  此外，Spring Security
  提供了多种经过生产验证的认证提供者和机制，这意味着您可以在部署时切换认证方式。
  这对于需要在未知目标环境中运行的产品的软件供应商来说尤其有价值。

- *Web 请求安全*: Servlet 规范提供了保护请求 URI 的方法。 然而，这些 URI
  只能以 Servlet 规范自身的有限 URI 路径格式表示。 Spring Security
  提供了更加全面的方法。 例如，您可以使用 Ant
  路径或正则表达式，可以考虑除请求页面之外的 URI 部分（例如， 可以考虑
  HTTP GET 参数），并且可以实现自己的运行时配置数据源。 这意味着您可以在
  Web 应用实际执行期间动态更改 Web 请求安全设置。

- *服务层和领域对象安全*: Servlet
  规范缺乏对服务层安全或领域对象实例安全的支持，这对多层应用是一个严重的限制。
  通常，开发者要么忽略这些需求，要么在 MVC
  控制器代码中实现安全逻辑（甚至更糟的是，在视图中实现）。这种做法存在严重缺点：

  - *关注点分离*: 授权是一种横切关注点，应相应地实现。 在 MVC
    控制器或视图中实现授权代码会使控制器和授权逻辑的测试更加困难，调试也更难，并且常常导致代码重复。

  - *对富客户端和 Web 服务的支持*:
    如果最终需要支持额外的客户端类型，则嵌入 Web
    层的任何授权代码都无法重用。 应该注意到，Spring
    远程导出器只导出服务层 Bean（不包括 MVC
    控制器）。因此，为了支持多种客户端类型，授权逻辑需要位于服务层。

  - *分层问题*: 在 MVC
    控制器或视图中实现针对服务层方法或领域对象实例的授权决策是错误的架构层。
    虽然可以将主体传递给服务层以使其做出授权决策，但这会在每个服务层方法上引入额外参数。
    更优雅的方法是使用 `ThreadLocal`
    来保存主体，尽管这可能会增加开发时间，以至于使用专用安全框架变得更为经济（从成本效益角度考虑）。

  - *授权代码质量*: 人们常说 Web
    框架\"\`让做正确的事情更容易，做错误的事情更难\`\"。安全框架也是如此，因为它们以抽象的方式设计，适用于广泛的目的。
    从头开始编写自己的授权代码不会提供框架所能提供的\"\`设计检查\`\"，内部授权代码通常缺乏通过广泛部署、同行评审和新版本而产生的改进。

对于简单的应用，Servlet 规范的安全性可能足够。 尽管考虑到 Web
容器可移植性、配置要求、有限的 Web
请求安全灵活性以及不存在的服务层和领域对象实例安全，为什么开发者经常寻求替代方案就显而易见了。

## 需要哪些 Java 和 Spring Framework 版本？ {#appendix-faq-requirements}

Spring Security 3.0 和 3.1 至少需要 JDK 1.5，并且至少需要 Spring 3.0.3。
理想情况下，您应使用最新的发布版本以避免问题。

Spring Security 2.0.x 需要最低 JDK 版本 1.4，并基于 Spring 2.0.x 构建。
它也应该与使用 Spring 2.5.x 的应用程序兼容。

### 我有一个复杂的场景。可能是什么问题？ {#appendix-faq-start-simple}

（这个答案通过处理一个具体场景来解决复杂场景的一般问题。）

假设您刚接触 Spring Security，需要构建一个支持 HTTPS 上 CAS
单点登录的应用程序，同时允许某些 URL
的本地基本认证，并对多个后端用户信息源（LDAP 和
JDBC）进行认证。您复制了一些配置文件，但发现它不起作用。可能是什么问题？

在成功使用这些技术构建应用程序之前，您需要先理解打算使用的技术。
安全性很复杂。 使用登录表单和一些硬编码用户通过 Spring Security
的命名空间进行简单配置是相对直接的。 迁移到使用后台 JDBC
数据库也同样容易。
但是，如果您试图直接跳到像这样的复杂部署场景，几乎肯定会感到沮丧。
设置诸如 CAS、配置 LDAP 服务器和正确安装 SSL
证书等系统所需的学习曲线有很大跳跃。 因此，您需要一步一步来。

从 Spring Security 的角度来看，您首先应该遵循网站上的\"\`入门指南\`\"。
这将带您完成一系列步骤，帮助您启动并运行，并让您了解框架的工作原理。
如果您使用其他不熟悉的技术，您应该做一些研究，并尝试确保在将它们组合到复杂系统之前能够独立使用它们。

# 常见问题 {#appendix-faq-common-problems}

本节讨论使用 Spring Security 时最常见的问题：

- 认证

  - [当我尝试登录时，我收到一条显示\"\`凭据错误\`\"的错误消息。哪里出错了？](#appendix-faq-bad-credentials)

  - [我的应用程序在我尝试登录时进入\"\`无限循环\`\"。发生了什么？](#appendix-faq-login-loop)

  - [我收到一条消息为 \"Access is denied (user is anonymous);\"
    的异常。哪里出错了？](#appendix-faq-anon-access-denied)

  - [为什么即使我已经退出应用程序，仍然可以看到受保护的页面？](#appendix-faq-cached-secure-page)

  - [我收到一条消息为 \"An Authentication object was not found in the
    SecurityContext\"
    的异常。哪里出错了？](#auth-exception-credentials-not-found)

  - [我无法使 LDAP
    认证工作。我的配置有什么问题？](#appendix-faq-ldap-authentication)

- 会话管理

  - [我正在使用 Spring Security
    的并发会话控制来防止用户同时多次登录。当我登录后打开另一个浏览器窗口时，它并没有阻止我再次登录。为什么我可以多次登录？](#appendix-faq-concurrent-session-same-browser)

  - [为什么通过 Spring Security 认证时会话 ID
    会改变？](#appendix-faq-new-session-on-authentication)

  - [我使用 Tomcat（或其他 Servlet 容器）并为我的登录页面启用了
    HTTPS，之后再切换回
    HTTP。它不起作用。认证后我最终又回到了登录页面。](#appendix-faq-tomcat-https-session)

  - [我正在尝试使用并发会话控制支持，但即使我确定已注销且未超过允许的会话数，也无法重新登录。哪里出错了？](#appendix-faq-session-listener-missing)

  - [尽管我已通过将 create-session 属性设置为 never 来配置 Spring
    Security
    不创建会话，但它仍会在某处创建会话。哪里出错了？](#appendix-faq-unwanted-session-creation)

- 其他

  - [执行 POST 时我收到 403
    Forbidden。哪里出错了？](#appendix-faq-forbidden-csrf)

  - [我正在使用 RequestDispatcher 将请求转发到另一个
    URL，但我的安全约束未被应用。](#appendix-faq-no-security-on-forward)

  - [我已将 Spring Security 的 \<global-method-security\>
    元素添加到我的应用程序上下文中，但如果我将安全注解添加到我的 Spring
    MVC 控制器 Bean（Struts
    动作等）中，它们似乎没有效果。为什么？](#appendix-faq-method-security-in-web-context)

  - [我有一个已明确认证的用户，但当我尝试在某些请求期间访问
    SecurityContextHolder 时，Authentication 为
    null。为什么我看不到用户信息？](#appendix-faq-no-filters-no-context)

  - [使用 URL 属性时，authorize JSP
    标签不尊重我的方法安全注解。为什么？](#appendix-faq-method-security-with-taglib)

## 当我尝试登录时，我收到一条显示\"\`凭据错误\`\"的错误消息。哪里出错了？ {#appendix-faq-bad-credentials}

这意味着认证失败了。
它没有说明原因，因为避免提供可能帮助攻击者猜测账户名或密码的详细信息是一种良好实践。

这也意味着，如果您在线提问，除非提供额外信息，否则不应期望得到答案。
对于任何问题，您都应该检查调试日志的输出，并注意任何异常堆栈跟踪和相关消息。
您应该使用调试器逐步执行代码，查看认证在哪里失败以及为什么失败。
您还应该编写一个测试用例，在应用程序外部测试您的认证配置。
如果使用哈希密码，请确保数据库中存储的值与应用程序中配置的
`PasswordEncoder` 生成的值_完全相同\_。

## 我的应用程序在我尝试登录时进入\"\`无限循环\`\"。发生了什么？ {#appendix-faq-login-loop}

无限循环和重定向到登录页面的一个常见用户问题是意外地将登录页面配置为\"\`受保护\`\"资源。
确保您的配置允许匿名访问登录页面，可以通过将其从安全过滤器链中排除或标记为需要
`ROLE_ANONYMOUS` 来实现。

如果您的 `AccessDecisionManager` 包含 `AuthenticatedVoter`，您可以使用
`IS_AUTHENTICATED_ANONYMOUSLY`
属性。如果使用标准的命名空间配置设置，此属性会自动可用。

从 Spring Security 2.0.1
开始，当您使用基于命名空间的配置时，加载应用程序上下文时会进行检查，如果您的登录页面似乎受保护，则会记录警告消息。

## 我收到一条消息为 \"Access is denied (user is anonymous);\" 的异常。哪里出错了？ {#appendix-faq-anon-access-denied}

这是一个调试级别的消息，首次匿名用户尝试访问受保护资源时发生。

    DEBUG [ExceptionTranslationFilter] - Access is denied (user is anonymous); redirecting to authentication entry point
    org.springframework.security.AccessDeniedException: Access is denied
    at org.springframework.security.vote.AffirmativeBased.decide(AffirmativeBased.java:68)
    at org.springframework.security.intercept.AbstractSecurityInterceptor.beforeInvocation(AbstractSecurityInterceptor.java:262)

这是正常的，无需担心。

## 为什么即使我已经退出应用程序，仍然可以看到受保护的页面？ {#appendix-faq-cached-secure-page}

最常见的原因是您的浏览器缓存了该页面，您看到的是从浏览器缓存中检索到的副本。
通过检查浏览器是否实际发送了请求（检查服务器访问日志和调试日志或使用适当的浏览器调试插件，如
Firefox 的 "Tamper Data"）来验证这一点。这与 Spring Security
无关，您应该配置您的应用程序或服务器以设置适当的 `Cache-Control`
响应头。 请注意，SSL 请求永远不会被缓存。

## 我收到一条消息为 \"An Authentication object was not found in the SecurityContext\" 的异常。哪里出错了？ {#auth-exception-credentials-not-found}

以下列表显示了另一个调试级别的消息，首次匿名用户尝试访问受保护资源时发生。然而，此列表显示了当您的过滤器链配置中没有
`AnonymousAuthenticationFilter` 时会发生的情况：

    DEBUG [ExceptionTranslationFilter] - Authentication exception occurred; redirecting to authentication entry point
    org.springframework.security.AuthenticationCredentialsNotFoundException:
                                An Authentication object was not found in the SecurityContext
    at org.springframework.security.intercept.AbstractSecurityInterceptor.credentialsNotFound(AbstractSecurityInterceptor.java:342)
    at org.springframework.security.intercept.AbstractSecurityInterceptor.beforeInvocation(AbstractSecurityInterceptor.java:254)

这是正常的，无需担心。

## 我无法使 LDAP 认证工作。我的配置有什么问题？ {#appendix-faq-ldap-authentication}

请注意，LDAP 目录的权限通常不允许读取用户的密码。 因此，通常不可能使用
[什么是
UserDetailsService，我需要它吗？](#appendix-faq-what-is-userdetailservice)，其中
Spring Security 将存储的密码与用户提交的密码进行比较。
最常见的方法是使用 LDAP "绑定"，这是 [LDAP
协议](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
支持的操作之一。使用这种方法，Spring Security
通过尝试以用户身份向目录进行认证来验证密码。

LDAP 认证中最常见的问题是缺乏对目录服务器树结构和配置的了解。
这因公司而异，因此您必须自己查明。 在向应用程序添加 Spring Security LDAP
配置之前，您应该使用标准 Java LDAP 代码（不涉及 Spring
Security）编写一个简单的测试，并确保首先使其正常工作。
例如，要认证用户，您可以使用以下代码：

::: informalexample

Java

:   ``` java
    @Test
    public void ldapAuthenticationIsSuccessful() throws Exception {
            Hashtable<String,String> env = new Hashtable<String,String>();
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, "cn=joe,ou=users,dc=mycompany,dc=com");
            env.put(Context.PROVIDER_URL, "ldap://mycompany.com:389/dc=mycompany,dc=com");
            env.put(Context.SECURITY_CREDENTIALS, "joespassword");
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

            InitialLdapContext ctx = new InitialLdapContext(env, null);

    }
    ```

Kotlin

:   ``` kotlin
    @Test
    fun ldapAuthenticationIsSuccessful() {
        val env = Hashtable<String, String>()
        env[Context.SECURITY_AUTHENTICATION] = "simple"
        env[Context.SECURITY_PRINCIPAL] = "cn=joe,ou=users,dc=mycompany,dc=com"
        env[Context.PROVIDER_URL] = "ldap://mycompany.com:389/dc=mycompany,dc=com"
        env[Context.SECURITY_CREDENTIALS] = "joespassword"
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        val ctx = InitialLdapContext(env, null)
    }
    ```
:::

## 会话管理 {#_会话管理}

会话管理问题是常见的疑问来源。 如果您正在开发 Java Web
应用程序，您应该了解会话如何在 Servlet 容器和用户浏览器之间维护。
您还应该了解安全 Cookie 和非安全 Cookie 之间的区别，以及使用 HTTP 和
HTTPS 并在这两者之间切换的影响。 Spring Security
与维护会话或提供会话标识符无关。 这完全由 Servlet 容器处理。

## 我正在使用 Spring Security 的并发会话控制来防止用户同时多次登录。当我登录后打开另一个浏览器窗口时，它并没有阻止我再次登录。为什么我可以多次登录？ {#appendix-faq-concurrent-session-same-browser}

浏览器通常为每个浏览器实例维护一个会话。 您不能同时拥有两个独立的会话。
因此，如果您在另一个窗口或标签页中再次登录，只是在同一会话中重新认证。
因此，如果您在另一个窗口或标签页中再次登录，您是在同一会话中重新认证。
服务器对标签页、窗口或浏览器实例一无所知。 它看到的只是 HTTP
请求，并根据其中包含的 `JSESSIONID` Cookie
的值将这些请求与特定会话关联起来。 当用户在会话中认证时，Spring Security
的并发会话控制会检查他们拥有的_其他已认证会话_的数量。
如果他们已经使用相同的会话进行了认证，重新认证不会产生任何效果。

## 为什么通过 Spring Security 认证时会话 ID 会改变？ {#appendix-faq-new-session-on-authentication}

在默认配置下，当用户认证时，Spring Security 会更改会话 ID。
如果您使用的是 Servlet 3.1 或更高版本的容器，会话 ID 会简单地更改。
如果您使用的是较旧的容器，Spring Security
会无效化现有会话，创建一个新会话，并将会话数据转移到新会话中。
以这种方式更改会话标识符可以防止\"\`会话固定\`\"攻击。
您可以在网上找到更多相关信息，也可以参考参考手册。

## 我使用 Tomcat（或其他 Servlet 容器）并为我的登录页面启用了 HTTPS，之后再切换回 HTTP。它不起作用。认证后我最终又回到了登录页面。 {#appendix-faq-tomcat-https-session}

它不起作用------认证后我最终又回到了登录页面。

这是因为为 HTTPS 创建的会话，其会话 Cookie
被标记为\"\`安全\`\"，随后无法在 HTTP 下使用。浏览器不会将 Cookie
发送回服务器，任何会话状态（包括安全上下文信息）都会丢失。首先在 HTTP
下启动会话应该可以工作，因为会话 Cookie 不会被标记为安全。 然而，Spring
Security 的
[会话固定保护](https://docs.spring.io/spring-security/site/docs/3.1.x/reference/springsecurity-single.html#ns-session-fixation)
可能会干扰这一点，因为它会导致新的会话 ID Cookie
被发送回用户的浏览器，通常带有安全标志。
要解决这个问题，您可以禁用会话固定保护。但在较新的 Servlet
容器中，您也可以配置会话 Cookie 从不使用安全标志。

:::: important
::: title
:::

一般来说，在 HTTP 和 HTTPS 之间切换不是一个好主意，因为任何使用 HTTP
的应用程序都容易受到中间人攻击。 为了真正安全，用户应该从 HTTPS
开始访问您的网站，并一直使用直到注销。 即使是点击通过 HTTP
访问的页面上的 HTTPS 链接也可能存在风险。 如果您需要更多说服力，请查看像
[sslstrip](https://github.com/moxie0/sslstrip/) 这样的工具。
::::

## 我没有在 HTTP 和 HTTPS 之间切换，但我的会话仍然丢失了。发生了什么？ {#_我没有在_http_和_https_之间切换但我的会话仍然丢失了发生了什么}

会话通过交换会话 Cookie 或在 URL 中添加 `jsessionid`
参数来维护（如果客户端禁用了 Cookie，并且您没有重写 URL 以包含
`jsessionid`，会话就会丢失。 请注意，出于安全原因，建议使用
Cookie，因为它不会在 URL 中暴露会话信息。

## 我正在尝试使用并发会话控制支持，但即使我确定已注销且未超过允许的会话数，也无法重新登录。哪里出错了？ {#appendix-faq-session-listener-missing}

确保您已在 `web.xml` 文件中添加了监听器。 必须确保在会话销毁时通知
Spring Security 会话注册表。 如果没有，会话信息不会从注册表中移除。
以下示例在 `web.xml` 文件中添加一个监听器：

``` xml
<listener>
        <listener-class>org.springframework.security.web.session.HttpSessionEventPublisher</listener-class>
</listener>
```

## 尽管我已通过将 create-session 属性设置为 never 来配置 Spring Security 不创建会话，但它仍会在某处创建会话。哪里出错了？ {#appendix-faq-unwanted-session-creation}

这通常意味着用户的应用程序在某处创建了会话，但他们并未意识到这一点。
最常见的罪魁祸首是 JSP。许多人不知道 JSP 默认会创建会话。 要防止 JSP
创建会话，请在页面顶部添加 `<%@ page session="false" %>` 指令。

如果您难以找出会话在何处创建，可以添加一些调试代码来追踪位置。一种方法是在应用程序中添加一个
`javax.servlet.http.HttpSessionListener`，在 `sessionCreated` 方法中调用
`Thread.dumpStack()`。

## 执行 POST 时我收到 403 Forbidden。哪里出错了？ {#appendix-faq-forbidden-csrf}

如果 HTTP POST 返回 HTTP 403 Forbidden 错误，但 HTTP GET
可以正常工作，问题很可能与
[CSRF](https://docs.spring.io/spring-security/site/docs/3.2.x/reference/htmlsingle/#csrf)
有关。要么提供 CSRF Token，要么禁用 CSRF 保护（后者不推荐）。

## 我正在使用 RequestDispatcher 将请求转发到另一个 URL，但我的安全约束未被应用。 {#appendix-faq-no-security-on-forward}

默认情况下，过滤器不会应用于转发或包含。
如果您确实希望安全过滤器应用于转发或包含，您必须在 `web.xml` 文件中使用
`<dispatcher>` 元素显式配置这些，该元素是 `<filter-mapping>`
元素的子元素。

## 我已将 Spring Security 的 \<global-method-security\> 元素添加到我的应用程序上下文中，但如果我将安全注解添加到我的 Spring MVC 控制器 Bean（Struts 动作等）中，它们似乎没有效果。为什么？ {#appendix-faq-method-security-in-web-context}

在 Spring Web 应用程序中，持有 DispatcherServlet 的 Spring MVC Bean
的应用程序上下文通常与主应用程序上下文分开。 它通常在名为
`myapp-servlet.xml` 的文件中定义，其中 `myapp` 是在 `web.xml`
文件中分配给 Spring `DispatcherServlet` 的名称。一个应用程序可以有多个
`DispatcherServlet` 实例，每个都有其独立的应用程序上下文。
这些\"\`子\`\"上下文中的 Bean 对应用程序的其余部分不可见。
\"\`父\`\"应用程序上下文由您在 `web.xml` 文件中定义的
`ContextLoaderListener` 加载，并对所有子上下文可见。
这通常是您定义安全配置（包括 `<global-method-security>` 元素）的地方。
因此，由于这些 Web Bean 无法从 `DispatcherServlet`
上下文中看到，因此对这些 Web Bean 中方法应用的任何安全约束都不会被执行。
您需要将 `<global-method-security>` 声明移动到 Web
上下文中，或将要保护的 Bean 移动到主应用程序上下文中。

通常，我们建议在服务层而不是单个 Web 控制器上应用方法安全。

## 我有一个已明确认证的用户，但当我尝试在某些请求期间访问 SecurityContextHolder 时，Authentication 为 null。为什么我看不到用户信息？ {#appendix-faq-no-filters-no-context}

为什么我看不到用户信息？

如果您通过在匹配 URL 模式的 `<intercept-url>` 元素中使用
`filters='none'` 属性将请求从安全过滤器链中排除，则该请求不会填充
`SecurityContextHolder`。 检查调试日志以查看请求是否通过过滤器链。
（您正在阅读调试日志，对吧？）

## 使用 URL 属性时，authorize JSP 标签不尊重我的方法安全注解。为什么？ {#appendix-faq-method-security-with-taglib}

使用 `<sec:authorize>` 中的 `url`
属性时，方法安全不会隐藏链接，因为我们无法轻易反向工程哪个 URL
映射到哪个控制器端点。我们受限于控制器可以依赖头部、当前用户和其他细节来确定要调用的方法。

# Spring Security 架构问题 {#appendix-faq-architecture}

本节讨论常见的 Spring Security 架构问题：

1.  [如何知道类 X 在哪个包中？](#appendix-faq-where-is-class-x)

2.  [命名空间元素如何映射到传统 Bean
    配置？](#appendix-faq-namespace-to-bean-mapping)

3.  [\"ROLE\_\"
    是什么意思，为什么我的角色名称需要它？](#appendix-faq-role-prefix)

4.  [如何知道需要向我的应用程序添加哪些依赖项才能与 Spring Security
    一起工作？](#appendix-faq-what-dependencies)

5.  [运行嵌入式 ApacheDS LDAP
    服务器需要哪些依赖项？](#appendix-faq-apacheds-deps)

6.  [什么是
    UserDetailsService，我需要它吗？](#appendix-faq-what-is-userdetailservice)

## 如何知道类 X 在哪个包中？ {#appendix-faq-where-is-class-x}

定位类的最佳方法是在您的 IDE 中安装 Spring Security
源码。发行版包含了项目划分的每个模块的源码 jar。
将这些添加到您的项目源路径中，然后您可以直接导航到 Spring Security
类（Eclipse 中按
Ctrl-Shift-T）。这也有助于调试，并让您通过直接查看发生异常的代码来排查问题。

## 命名空间元素如何映射到传统 Bean 配置？ {#appendix-faq-namespace-to-bean-mapping}

参考指南的命名空间附录中有一般概述，说明命名空间创建了哪些 Bean。
还有一个详细的博客文章叫做 \"Behind the Spring Security
Namespace\"，位于
[blog.springsource.com](https://spring.io/blog/2010/03/06/behind-the-spring-security-namespace/)。如果您想了解完整的细节，代码位于
Spring Security 3.0 发行版中的 `spring-security-config` 模块内。
您可能应该先阅读标准 Spring Framework 参考文档中关于命名空间解析的章节。

## \"ROLE\_\" 是什么意思，为什么我的角色名称需要它？ {#appendix-faq-role-prefix}

Spring Security 采用基于投票者的架构，这意味着访问决策由一系列
`AccessDecisionVoter` 实例做出。
投票者作用于\"\`配置属性\`\"，这些属性为受保护资源（如方法调用）指定。采用这种方法，并非所有属性都与所有投票者相关，投票者需要知道何时应忽略某个属性（弃权）以及何时应根据属性值投票授予或拒绝访问。
最常见的投票者是 `RoleVoter`，默认情况下，只要找到带有 `ROLE_`
前缀的属性，它就会投票。 它将属性（如
`ROLE_USER`）与当前用户被分配的权限名称进行简单比较。
如果找到匹配项（他们有一个名为 `ROLE_USER`
的权限），则投票授予访问权限。否则，投票拒绝访问。

您可以通过设置 `RoleVoter` 的 `rolePrefix`
属性来更改前缀。如果您只需要在应用程序中使用角色并且不需要其他自定义投票者，可以将前缀设置为空字符串。在这种情况下，`RoleVoter`
将所有属性视为角色。

## 如何知道需要向我的应用程序添加哪些依赖项才能与 Spring Security 一起工作？ {#appendix-faq-what-dependencies}

这取决于您使用的功能和正在开发的应用程序类型。 使用 Spring Security
3.0，项目 jar
被划分为明确的功能区域，因此很容易根据您的应用程序需求确定需要哪些
Spring Security jar。 所有应用程序都需要 `spring-security-core` jar。
如果您正在开发 Web 应用程序，您需要 `spring-security-web` jar。
如果您使用安全命名空间配置，您需要 `spring-security-config` jar。对于
LDAP 支持，您需要 `spring-security-ldap` jar。依此类推。

对于第三方 jar，情况并不总是那么明显。
一个好的起点是从预构建的示例应用程序的 `WEB-INF/lib` 目录中复制它们。
对于基本应用程序，您可以从教程示例开始。
对于基本应用程序，您可以从教程示例开始。
如果您想使用带有嵌入式测试服务器的 LDAP，请以 LDAP 示例作为起点。
参考手册还包括 [一个附录](#appendix-namespace)，列出了每个 Spring
Security
模块的一级依赖项，并提供了一些关于它们是否可选以及何时需要的信息。

如果您使用 Maven 构建项目，将适当的 Spring Security
模块作为依赖项添加到您的 `pom.xml` 文件中会自动拉取框架所需的 core jar。
任何在 Spring Security `pom.xml`
文件中标记为\"\`可选\`\"的依赖项，如果需要，必须手动添加到您自己的
`pom.xml` 文件中。

## 运行嵌入式 ApacheDS LDAP 服务器需要哪些依赖项？ {#appendix-faq-apacheds-deps}

如果您使用 Maven，需要将以下内容添加到您的 `pom.xml` 文件依赖项中：

    <dependency>
            <groupId>org.apache.directory.server</groupId>
            <artifactId>apacheds-core</artifactId>
            <version>1.5.5</version>
            <scope>runtime</scope>
    </dependency>
    <dependency>
            <groupId>org.apache.directory.server</groupId>
            <artifactId>apacheds-server-jndi</artifactId>
            <version>1.5.5</version>
            <scope>runtime</scope>
    </dependency>

其他所需的 jar 应该会自动传递拉取。

## 什么是 UserDetailsService，我需要它吗？ {#appendix-faq-what-is-userdetailservice}

`UserDetailsService` 是一个 DAO 接口，用于加载特定于用户账户的数据。
它的唯一功能是为框架内的其他组件加载这些数据以供使用。
它不负责认证用户。 使用用户名和密码组合认证用户最常由
`DaoAuthenticationProvider` 执行，该提供者注入了 `UserDetailsService`
以使其加载用户的密码（及其他数据），并与提交的值进行比较。
请注意，如果您使用
LDAP，[这种方法可能不适用](#appendix-faq-ldap-authentication)。

如果您想自定义认证过程，您应该自己实现 `AuthenticationProvider`。 有关将
Spring Security 认证与 Google App Engine 集成的示例，请参阅此
[博客文章](https://spring.io/blog/2010/08/02/spring-security-in-google-app-engine/)。

# 常见的"如何做"问题 {#appendix-faq-howto}

本节讨论关于 Spring Security 的常见"如何做"问题：

1.  [我需要使用比仅用户名更多的信息进行登录。如何添加对额外登录字段（如公司名称）的支持？](#appendix-faq-extra-login-fields)

2.  [如何在仅请求 URL 的片段值不同的地方应用不同的 intercept-url
    约束（如 /thing1#thing2 和
    /thing1#thing3）？](#appendix-faq-matching-url-fragments)

3.  [如何在 UserDetailsService 中访问用户的 IP 地址（或其他 Web
    请求数据）？](#appendix-faq-request-details-in-user-service)

4.  [如何从 UserDetailsService 访问
    HttpSession？](#appendix-faq-access-session-from-user-service)

5.  [如何在 UserDetailsService
    中访问用户的密码？](#appendix-faq-password-in-user-service)

6.  [如何在应用程序中动态定义受保护的
    URL？](#appendix-faq-dynamic-url-metadata)

7.  [如何对 LDAP
    进行认证但从数据库加载用户角色？](#appendix-faq-ldap-authorities)

8.  [我想修改由命名空间创建的 Bean
    的属性，但模式中没有支持它的内容。除了放弃使用命名空间外，我还能做什么？](#appendix-faq-namespace-post-processor)

## 我需要使用比仅用户名更多的信息进行登录。如何添加对额外登录字段（如公司名称）的支持？ {#appendix-faq-extra-login-fields}

这个问题反复出现，因此您可以通过在线搜索找到更多信息。

提交的登录信息由 `UsernamePasswordAuthenticationFilter`
实例处理。您需要自定义此类以处理额外的数据字段。一种选择是使用您自己的自定义认证令牌类（而不是标准的
`UsernamePasswordAuthenticationToken`）。另一种选择是将额外字段与用户名连接（例如，使用
`:` 字符作为分隔符）并将其传递给 `UsernamePasswordAuthenticationToken`
的用户名属性。

您还需要自定义实际的认证过程。
例如，如果您使用自定义认证令牌类，则必须编写一个
`AuthenticationProvider`（或扩展标准的
`DaoAuthenticationProvider`）来处理它。如果您已连接字段，则可以实现自己的
`UserDetailsService` 来拆分它们并加载适当的用户数据以进行认证。

## 如何在仅请求 URL 的片段值不同的地方应用不同的 intercept-url 约束（如 /thing1#thing2 和 /thing1#thing3）？ {#appendix-faq-matching-url-fragments}

您无法做到这一点，因为片段不会从浏览器传输到服务器。
从服务器的角度来看，这些 URL 是相同的。 这是 GWT 用户常见的问题。

## 如何在 UserDetailsService 中访问用户的 IP 地址（或其他 Web 请求数据）？ {#appendix-faq-request-details-in-user-service}

您无法做到（除非使用类似 thread-local
变量的方法），因为接口提供的唯一信息是用户名。 相反，您应该直接实现
`AuthenticationProvider` 并从提供的 `Authentication` 令牌中提取信息。

在标准的 Web 设置中，`Authentication` 对象上的 `getDetails()` 方法将返回
`WebAuthenticationDetails` 的实例。如果您需要额外的信息，可以将自定义的
`AuthenticationDetailsSource` 注入到您使用的认证过滤器中。
例如，如果您使用命名空间和 `<form-login>`
元素，则应移除此元素并用指向显式配置的
`UsernamePasswordAuthenticationFilter` 的 `<custom-filter>` 声明替换它。

## 如何从 UserDetailsService 访问 HttpSession？ {#appendix-faq-access-session-from-user-service}

您无法做到，因为 `UserDetailsService` 对 Servlet API
没有感知。如果您想存储自定义用户数据，您应该自定义返回的 `UserDetails`
对象。 然后可以在任何时候通过线程局部变量 `SecurityContextHolder`
访问此自定义对象。 调用
`SecurityContextHolder.getContext().getAuthentication().getPrincipal()`
将返回此自定义对象。

如果您真的需要访问会话，您必须通过自定义 Web 层来实现。

## 如何在 UserDetailsService 中访问用户的密码？ {#appendix-faq-password-in-user-service}

您无法做到（即使找到了方法也不应该这样做）。您可能误解了它的用途。
请参见 FAQ 中前面的\"[什么是
UserDetailsService?](#appendix-faq-what-is-userdetailservice)\"。

## 如何在应用程序中动态定义受保护的 URL？ {#appendix-faq-dynamic-url-metadata}

人们经常询问如何将受保护 URL
与安全元数据属性的映射存储在数据库中，而不是应用程序上下文中。

您首先应该问自己是否真的需要这样做。
如果一个应用程序需要安全，也需要根据定义的策略进行全面的安全测试。
它可能需要审计和验收测试后才能投入生产环境。
注重安全的组织应该意识到，通过修改配置数据库中的几行来在运行时修改安全设置，可能会立即消除其勤奋测试过程的好处。
如果您已考虑到这一点（也许通过在应用程序内使用多层安全），Spring
Security 允许您完全自定义安全元数据的来源。 您可以选择使其完全动态。

方法和 Web 安全都由 `AbstractSecurityInterceptor`
的子类保护，该拦截器配置了
`SecurityMetadataSource`，从中获取特定方法或过滤器调用的元数据。 对于
Web 安全，拦截器类是 `FilterSecurityInterceptor`，它使用
`FilterInvocationSecurityMetadataSource`
标记接口。它操作的\"\`安全对象\`\"类型是
`FilterInvocation`。默认实现（在命名空间 `<http>`
和显式配置拦截器时使用）将 URL
模式列表及其对应的\"\`配置属性\`\"列表（`ConfigAttribute`
的实例）存储在内存映射中。

要从替代源加载数据，您必须使用显式声明的安全过滤器链（通常是 Spring
Security 的 `FilterChainProxy`）来自定义 `FilterSecurityInterceptor`
Bean。 您不能使用命名空间。 然后您需要实现
`FilterInvocationSecurityMetadataSource`，以便根据您的喜好为特定的
`FilterInvocation` 加载数据。`FilterInvocation` 对象包含
`HttpServletRequest`，因此您可以获取 URL
或任何其他相关信息，以决定返回属性列表的内容。基本轮廓如下所示：

::: informalexample

Java

:   ``` java
      public class MyFilterSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

            public List<ConfigAttribute> getAttributes(Object object) {
                FilterInvocation fi = (FilterInvocation) object;
                    String url = fi.getRequestUrl();
                    String httpMethod = fi.getRequest().getMethod();
                    List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>();

                    // 使用此信息查找您的数据库（或其他源）并填充
                    // 属性列表

                    return attributes;
            }

            public Collection<ConfigAttribute> getAllConfigAttributes() {
                return null;
            }

            public boolean supports(Class<?> clazz) {
                return FilterInvocation.class.isAssignableFrom(clazz);
            }
        }
    ```

Kotlin

:   ``` kotlin
    class MyFilterSecurityMetadataSource : FilterInvocationSecurityMetadataSource {
        override fun getAttributes(securedObject: Any): List<ConfigAttribute> {
            val fi = securedObject as FilterInvocation
            val url = fi.requestUrl
            val httpMethod = fi.request.method

            // 使用此信息查找您的数据库（或其他源）并填充
            // 属性列表
            return ArrayList()
        }

        override fun getAllConfigAttributes(): Collection<ConfigAttribute>? {
            return null
        }

        override fun supports(clazz: Class<*>): Boolean {
            return FilterInvocation::class.java.isAssignableFrom(clazz)
        }
    }
    ```
:::

有关更多信息，请查看 `DefaultFilterInvocationSecurityMetadataSource`
的代码。

## 如何对 LDAP 进行认证但从数据库加载用户角色？ {#appendix-faq-ldap-authorities}

`LdapAuthenticationProvider` Bean（在 Spring Security 中处理常规 LDAP
认证）配置了两个独立的策略接口，一个执行认证，另一个加载用户权限，分别称为
`LdapAuthenticator` 和 `LdapAuthoritiesPopulator`。
`DefaultLdapAuthoritiesPopulator` 从 LDAP
目录加载用户权限，并具有各种配置参数，让您指定如何检索这些权限。

要改用 JDBC，您可以自己实现该接口，使用适合您模式的任何 SQL：

::: informalexample

Java

:   ``` java
    public class MyAuthoritiesPopulator implements LdapAuthoritiesPopulator {
        @Autowired
        JdbcTemplate template;

        List<GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
            return template.query("select role from roles where username = ?",
                    new String[] {username},
                    new RowMapper<GrantedAuthority>() {
                 /**
                 *  我们在这里假设您使用标准约定，即使用角色
                 *  前缀 "ROLE_" 来标记由 Spring Security 的 RoleVoter 支持的属性。
                 */
                @Override
                public GrantedAuthority mapRow(ResultSet rs, int rowNum) throws SQLException {
                    return new SimpleGrantedAuthority("ROLE_" + rs.getString(1));
                }
            });
        }
    }
    ```

Kotlin

:   ``` kotlin
    class MyAuthoritiesPopulator : LdapAuthoritiesPopulator {
        @Autowired
        lateinit var template: JdbcTemplate

        override fun getGrantedAuthorities(userData: DirContextOperations, username: String): MutableList<GrantedAuthority?> {
            return template.query("select role from roles where username = ?",
                arrayOf(username)
            ) { rs, _ ->
                /**
                 * 我们在这里假设您使用标准约定，即使用角色
                 * 前缀 "ROLE_" 来标记由 Spring Security 的 RoleVoter 支持的属性。
                 */
                SimpleGrantedAuthority("ROLE_" + rs.getString(1))
            }
        }
    }
    ```
:::

然后，您需要将此类型的 Bean 添加到您的应用程序上下文中，并将其注入到
`LdapAuthenticationProvider` 中。这在参考手册的 LDAP 章节中关于使用显式
Spring Bean 配置 LDAP 的部分有所介绍。
请注意，在这种情况下，您不能使用命名空间进行配置。
您还应该查阅相关类和接口的 {security-api-url}\[Javadoc\]。

## 我想修改由命名空间创建的 Bean 的属性，但模式中没有支持它的内容。除了放弃使用命名空间外，我还能做什么？ {#appendix-faq-namespace-post-processor}

命名空间功能有意限制，因此它不涵盖使用普通 Bean 可以做的所有事情。
如果您想做一些简单的事情，比如修改 Bean
或注入不同的依赖项，可以通过向配置中添加 `BeanPostProcessor` 来实现。
您可以在 [Spring
参考手册](https://docs.spring.io/spring/docs/3.0.x/spring-framework-reference/htmlsingle/spring-framework-reference.html#beans-factory-extension-bpp)
中找到更多信息。为此，您需要了解创建了哪些
Bean，因此您还应该阅读前面关于 [命名空间如何映射到 Spring
Bean](#appendix-faq-namespace-to-bean-mapping) 的问题中提到的博客文章。

通常，您会将所需的功能添加到 `BeanPostProcessor` 的
`postProcessBeforeInitialization` 方法中。假设您想自定义
`UsernamePasswordAuthenticationFilter`（由 `form-login` 元素创建）使用的
`AuthenticationDetailsSource`。您想从请求中提取一个名为 `CUSTOM_HEADER`
的特定头部，并在认证用户时使用它。 处理器类看起来像以下列表：

::: informalexample

Java

:   ``` java
    public class CustomBeanPostProcessor implements BeanPostProcessor {

            public Object postProcessAfterInitialization(Object bean, String name) {
                    if (bean instanceof UsernamePasswordAuthenticationFilter) {
                            System.out.println("********* Post-processing " + name);
                            ((UsernamePasswordAuthenticationFilter)bean).setAuthenticationDetailsSource(
                                            new AuthenticationDetailsSource() {
                                                    public Object buildDetails(Object context) {
                                                            return ((HttpServletRequest)context).getHeader("CUSTOM_HEADER");
                                                    }
                                            });
                    }
                    return bean;
            }

            public Object postProcessBeforeInitialization(Object bean, String name) {
                    return bean;
            }
    }
    ```

Kotlin

:   ``` kotlin
    class CustomBeanPostProcessor : BeanPostProcessor {
        override fun postProcessAfterInitialization(bean: Any, name: String): Any {
            if (bean is UsernamePasswordAuthenticationFilter) {
                println("********* Post-processing $name")
                bean.setAuthenticationDetailsSource(
                    AuthenticationDetailsSource<HttpServletRequest, Any?> { context -> context.getHeader("CUSTOM_HEADER") })
            }
            return bean
        }

        override fun postProcessBeforeInitialization(bean: Any, name: String?): Any {
            return bean
        }
    }
    ```
:::

然后，您需要在应用程序上下文中注册此 Bean。 Spring
会自动在应用程序上下文中定义的 Bean 上调用它。
