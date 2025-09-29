# 概述 {#cas-overview}

JA-SIG 开发了一种名为 CAS 的企业级单点登录系统。 与其他方案不同，JA-SIG
的中央认证服务（Central Authentication
Service）是开源的、广泛使用、易于理解、平台无关，并支持代理功能。 Spring
Security 完全支持 CAS，能够轻松地将 Spring Security
从单应用部署迁移到由企业级 CAS 服务器保护的多应用部署。

您可以在 <https://www.apereo.org> 了解更多关于 CAS 的信息。
您还需要访问该网站以下载 CAS 服务器文件。

# CAS 的工作原理 {#cas-how-it-works}

虽然 CAS 网站包含详细说明其架构的文档，但我们在 Spring Security
的上下文中再次提供一个总体概述。 Spring Security 3.x 支持 CAS 3。
在编写本文时，CAS 服务器版本为 3.4。

在您的企业中的某个位置需要设置一个 CAS 服务器。 CAS 服务器只是一个标准的
WAR 文件，因此搭建服务器并不复杂。 在 WAR
文件中，您可以自定义向用户显示的登录页面和其他单点登录页面。

当部署 CAS 3.4 服务器时，您还需要在 CAS 提供的
`deployerConfigContext.xml` 文件中指定一个 `AuthenticationHandler`。
`AuthenticationHandler` 包含一个简单的方法，用于判断给定凭据是否有效。
您的 `AuthenticationHandler` 实现需要连接到某种后端认证存储库，例如 LDAP
服务器或数据库。 CAS 自身已经内置了多种 `AuthenticationHandler`
来帮助实现这一点。 当您下载并部署服务器 WAR
文件时，默认会配置为：只要用户输入的密码与其用户名相同即可成功认证，这在测试时非常有用。

除了 CAS 服务器本身外，其他关键参与者自然是部署在整个企业中的安全 Web
应用程序。 这些 Web 应用被称为"服务"。
服务分为三种类型：验证服务票据的服务、获取代理票据的服务，以及验证代理票据的服务。
验证代理票据有所不同，因为必须验证代理列表，而且通常代理票据可以重复使用。

## Spring Security 与 CAS 的交互流程 {#cas-sequence}

Web 浏览器、CAS 服务器和 Spring Security 保护的服务之间的基本交互如下：

- 用户正在浏览服务的公开页面。 此时 CAS 或 Spring Security 尚未介入。

- 用户最终请求了一个受保护的页面，或使用了某个受保护的 Bean。 Spring
  Security 的 `ExceptionTranslationFilter` 将检测到
  `AccessDeniedException` 或 `AuthenticationException`。

- 由于用户的 `Authentication` 对象（或缺失）导致了
  `AuthenticationException`，`ExceptionTranslationFilter` 将调用配置的
  `AuthenticationEntryPoint`。 如果使用 CAS，则为
  `CasAuthenticationEntryPoint` 类。

- `CasAuthenticationEntryPoint` 将重定向用户的浏览器至 CAS
  服务器，并附带一个 `service` 参数，即 Spring Security
  服务（您的应用程序）的回调 URL。 例如，浏览器被重定向的 URL
  可能是：https://my.company.com/cas/login?service=https%3A%2F%2Fserver3.company.com%2Fwebapp%2Flogin/cas。

- 当用户浏览器重定向到 CAS 后，将提示输入用户名和密码。
  如果用户携带了一个表示之前已登录的会话
  Cookie，则不会再次要求登录（此过程存在例外情况，稍后会介绍）。 CAS
  将使用上述讨论的 `PasswordHandler`（或 CAS 3.0 中的
  `AuthenticationHandler`）来判断用户名和密码是否有效。

- 登录成功后，CAS 将把用户浏览器重定向回原始服务，并附带一个 `ticket`
  参数，这是一个代表"服务票据"的不透明字符串。
  继续上面的例子，浏览器可能被重定向到：https://server3.company.com/webapp/login/cas?ticket=ST-0-ER94xMJmn6pha35CQRoZ。

- 回到服务 Web 应用程序中，`CasAuthenticationFilter` 始终监听
  `/login/cas` 请求（可配置，但在本介绍中我们使用默认值）。
  处理过滤器将构建一个代表服务票据的
  `UsernamePasswordAuthenticationToken`。 其中主体（principal）等于
  `CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER`，凭据（credentials）为服务票据的不透明值。
  然后该认证请求将交给配置的 `AuthenticationManager` 处理。

- `AuthenticationManager` 的实现通常是 `ProviderManager`，它又配置了
  `CasAuthenticationProvider`。 `CasAuthenticationProvider` 仅响应包含
  CAS 特定主体（如 `CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER`）的
  `UsernamePasswordAuthenticationToken` 和稍后讨论的
  `CasAuthenticationToken`。

- `CasAuthenticationProvider` 将使用 `TicketValidator`
  实现来验证服务票据。 通常为 `Cas20ServiceTicketValidator`，这是 CAS
  客户端库中包含的类之一。 如果应用需要验证代理票据，则使用
  `Cas20ProxyTicketValidator`。 `TicketValidator` 通过 HTTPS 请求 CAS
  服务器以验证服务票据。 它还可以包含一个代理回调
  URL，例如：https://my.company.com/cas/proxyValidate?service=https%3A%2F%2Fserver3.company.com%2Fwebapp%2Flogin/cas&ticket=ST-0-ER94xMJmn6pha35CQRoZ&pgtUrl=https://server3.company.com/webapp/login/cas/proxyreceptor。

- 在 CAS 服务器端，验证请求将被接收。
  如果提供的服务票据匹配票据签发时对应的服务 URL，CAS 将返回一个 XML
  格式的肯定响应，包含用户名。
  如果有任何代理参与了认证（见下文），代理列表也会包含在 XML 响应中。

- \[可选\] 如果对 CAS 验证服务的请求包含了代理回调 URL（通过 `pgtUrl`
  参数），CAS 将在 XML 响应中包含一个 `pgtIou` 字符串。 这个 `pgtIou`
  代表代理授予票据的借据（IOU）。 CAS 服务器随后将创建自己的 HTTPS
  连接回到 `pgtUrl`，以实现 CAS 服务器与声称的服务 URL 的相互认证。 该
  HTTPS 连接将用于向原始 Web 应用发送代理授予票据。
  例如：https://server3.company.com/webapp/login/cas/proxyreceptor?pgtIou=PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt&pgtId=PGT-1-si9YkkHLrtACBo64rmsi3v2nf7cpCResXg5MpESZFArbaZiOKH。

- `Cas20TicketValidator` 将解析从 CAS 服务器收到的 XML。 它将返回一个
  `TicketResponse` 给
  `CasAuthenticationProvider`，其中包含用户名（必需）、代理列表（如有）和代理授予票据
  IOU（如请求了代理回调）。

- 接着，`CasAuthenticationProvider` 将调用配置的 `CasProxyDecider`。
  `CasProxyDecider` 用于判断 `TicketResponse`
  中的代理列表是否被服务接受。 Spring Security
  提供了多个实现：`RejectProxyTickets`、`AcceptAnyCasProxy` 和
  `NamedCasProxyDecider`。 这些名称基本自解释，除了
  `NamedCasProxyDecider`，它允许提供一个可信代理的 `List`。

- `CasAuthenticationProvider` 接下来将请求一个
  `AuthenticationUserDetailsService` 来加载适用于 `Assertion` 中用户的
  `GrantedAuthority` 对象。

- 如果没有问题，`CasAuthenticationProvider` 将构造一个
  `CasAuthenticationToken`，包含 `TicketResponse` 中的详细信息以及
  `GrantedAuthority`。

- 控制权返回给 `CasAuthenticationFilter`，后者将创建的
  `CasAuthenticationToken` 放入安全上下文中。

- 用户浏览器被重定向到最初引发 `AuthenticationException`
  的页面（或根据配置的自定义目标页面）。

很高兴你还在继续阅读！ 接下来我们看看如何进行配置。

# CAS 客户端配置 {#cas-client}

由于 Spring Security 的存在，Web 应用端的 CAS 配置变得非常简单。
假设您已经了解了使用 Spring Security 的基础知识，因此以下不再赘述。
我们将假设使用基于命名空间的配置，并按需添加 CAS 相关的 Bean。
每个部分都建立在前一部分的基础上。 完整的 CAS 示例应用程序可在 Spring
Security [示例](samples.xml#samples) 中找到。

## 服务票据认证 {#cas-st}

本节描述如何设置 Spring Security 以认证服务票据。 大多数 Web
应用只需要这一功能。 您需要在应用上下文中添加一个 `ServiceProperties`
Bean。 它代表您的 CAS 服务：

``` xml
<bean id="serviceProperties"
    class="org.springframework.security.cas.ServiceProperties">
<property name="service"
    value="https://localhost:8443/cas-sample/login/cas"/>
<property name="sendRenew" value="false"/>
</bean>
```

`service` 必须等于由 `CasAuthenticationFilter` 监听的 URL。 `sendRenew`
默认为 false，但如果您的应用特别敏感，则应设为 true。 此参数的作用是告诉
CAS
登录服务，单点登录登录不可接受，用户必须重新输入用户名和密码才能访问服务。

以下 Bean 应配置为启动 CAS 认证流程（假设您使用命名空间配置）：

``` xml
<security:http entry-point-ref="casEntryPoint">
...
<security:custom-filter position="CAS_FILTER" ref="casFilter" />
</security:http>

<bean id="casFilter"
    class="org.springframework.security.cas.web.CasAuthenticationFilter">
<property name="authenticationManager" ref="authenticationManager"/>
</bean>

<bean id="casEntryPoint"
    class="org.springframework.security.cas.web.CasAuthenticationEntryPoint">
<property name="loginUrl" value="https://localhost:9443/cas/login"/>
<property name="serviceProperties" ref="serviceProperties"/>
</bean>
```

要使 CAS 正常运行，`ExceptionTranslationFilter` 的
`authenticationEntryPoint` 属性必须设置为 `CasAuthenticationEntryPoint`
Bean。 这可以通过使用
[entry-point-ref](servlet/appendix/namespace/http.xml#nsa-http-entry-point-ref)
轻松实现，如上例所示。 `CasAuthenticationEntryPoint` 必须引用
`ServiceProperties` Bean（如上所述），它提供指向企业 CAS 登录服务器的
URL，用户浏览器将被重定向至此。

`CasAuthenticationFilter` 的属性与
`UsernamePasswordAuthenticationFilter`（用于基于表单的登录）非常相似。
您可以使用这些属性来自定义认证成功或失败时的行为。

接下来需要添加 `CasAuthenticationProvider` 及其协作者：

``` xml
<security:authentication-manager alias="authenticationManager">
<security:authentication-provider ref="casAuthenticationProvider" />
</security:authentication-manager>

<bean id="casAuthenticationProvider"
    class="org.springframework.security.cas.authentication.CasAuthenticationProvider">
<property name="authenticationUserDetailsService">
    <bean class="org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper">
    <constructor-arg ref="userService" />
    </bean>
</property>
<property name="serviceProperties" ref="serviceProperties" />
<property name="ticketValidator">
    <bean class="org.apereo.cas.client.validation.Cas20ServiceTicketValidator">
    <constructor-arg index="0" value="https://localhost:9443/cas" />
    </bean>
</property>
<property name="key" value="an_id_for_this_auth_provider_only"/>
</bean>

<security:user-service id="userService">
<!-- Password is prefixed with {noop} to indicate to DelegatingPasswordEncoder that
NoOpPasswordEncoder should be used.
This is not safe for production, but makes reading
in samples easier.
Normally passwords should be hashed using BCrypt -->
<security:user name="joe" password="{noop}joe" authorities="ROLE_USER" />
...
</security:user-service>
```

`CasAuthenticationProvider` 使用 `UserDetailsService` 实例在用户通过 CAS
认证后加载其权限。 这里我们展示了一个简单的内存配置。
请注意，`CasAuthenticationProvider`
实际上并不使用密码进行认证，但它确实使用权限信息。

如果您回顾 [How CAS Works](#cas-how-it-works) 部分，这些 Bean
的作用都是相当直观的。

这完成了 CAS 最基本的配置。 如果没有出错，您的 Web 应用将在 CAS
单点登录框架内正常工作。 Spring Security 的其他部分无需关心 CAS
已处理认证的事实。 接下来的部分我们将讨论一些（可选的）更高级的配置。

## 单点登出 {#cas-singlelogout}

CAS 协议支持单点登出（Single Logout），可以轻松添加到您的 Spring
Security 配置中。 以下是处理单点登出的 Spring Security 配置更新：

``` xml
<security:http entry-point-ref="casEntryPoint">
...
<security:logout logout-success-url="/cas-logout.jsp"/>
<security:custom-filter ref="requestSingleLogoutFilter" before="LOGOUT_FILTER"/>
<security:custom-filter ref="singleLogoutFilter" before="CAS_FILTER"/>
</security:http>

<!-- This filter handles a Single Logout Request from the CAS Server -->
<bean id="singleLogoutFilter" class="org.apereo.cas.client.session.SingleSignOutFilter"/>

<!-- This filter redirects to the CAS Server to signal Single Logout should be performed -->
<bean id="requestSingleLogoutFilter"
    class="org.springframework.security.web.authentication.logout.LogoutFilter">
<constructor-arg value="https://localhost:9443/cas/logout"/>
<constructor-arg>
    <bean class=
        "org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler"/>
</constructor-arg>
<property name="filterProcessesUrl" value="/logout/cas"/>
</bean>
```

`logout` 元素会将用户从本地应用登出，但不会结束与 CAS
服务器或其他已登录应用的会话。 `requestSingleLogoutFilter`
过滤器允许请求 `/spring_security_cas_logout` URL，将应用重定向到配置的
CAS 服务器登出 URL。 然后 CAS
服务器会向所有已登录的服务发送单点登出请求。 `singleLogoutFilter`
通过查找静态 `Map` 中的 `HttpSession` 并使其失效来处理单点登出请求。

可能会困惑为什么既需要 `logout` 元素又需要 `singleLogoutFilter`。
最佳实践是先在本地登出，因为 `SingleSignOutFilter` 只是将 `HttpSession`
存储在静态 `Map` 中以便调用其 `invalidate` 方法。
使用以上配置，登出流程如下：

- 用户请求 `/logout`，这会将用户从本地应用登出，并跳转到登出成功页面。

- 登出成功页面 `/cas-logout.jsp` 应指示用户点击一个指向 `/logout/cas`
  的链接，以登出所有应用。

- 当用户点击链接时，用户被重定向到 CAS 单点登出
  URL（https://localhost:9443/cas/logout）。

- 在 CAS 服务器端，CAS 单点登出 URL 向所有 CAS 服务提交单点登出请求。

- 在 CAS 服务端，Apereo 的 `SingleSignOutFilter`
  通过使原始会话失效来处理登出请求。

下一步是在您的 `web.xml` 中添加以下内容：

``` xml
<filter>
<filter-name>characterEncodingFilter</filter-name>
<filter-class>
    org.springframework.web.filter.CharacterEncodingFilter
</filter-class>
<init-param>
    <param-name>encoding</param-name>
    <param-value>UTF-8</param-value>
</init-param>
</filter>
<filter-mapping>
<filter-name>characterEncodingFilter</filter-name>
<url-pattern>/*</url-pattern>
</filter-mapping>
<listener>
<listener-class>
    org.apereo.cas.client.session.SingleSignOutHttpSessionListener
</listener-class>
</listener>
```

使用 `SingleSignOutFilter` 时可能会遇到编码问题。 因此建议添加
`CharacterEncodingFilter`，以确保在使用 `SingleSignOutFilter`
时字符编码正确。 详情请参考 Apereo CAS 文档。
`SingleSignOutHttpSessionListener` 确保当 `HttpSession`
过期时，用于单点登出的映射会被移除。

## 使用 CAS 向无状态服务认证 {#cas-pt-client}

本节描述如何使用 CAS 向服务进行认证。
换句话说，本节讨论如何设置客户端以使用通过 CAS 认证的服务。
下一节将介绍如何设置无状态服务以使用 CAS 进行认证。

### 配置 CAS 获取代理授予票据 {#cas-pt-client-config}

为了向无状态服务认证，应用需要获取代理授予票据（PGT）。 本节描述如何配置
Spring Security 以获取 PGT，基于前面的 cas-st\[服务票据认证\]
配置进行扩展。

第一步是在 Spring Security 配置中包含一个 `ProxyGrantingTicketStorage`。
它用于存储 `CasAuthenticationFilter` 获取的
PGT，以便后续用于获取代理票据。 示例配置如下：

``` xml
<!--
NOTE: In a real application you should not use an in memory implementation.
You will also want to ensure to clean up expired tickets by calling
ProxyGrantingTicketStorage.cleanup()
-->
<bean id="pgtStorage" class="org.apereo.cas.client.proxy.ProxyGrantingTicketStorageImpl"/>
```

第二步是更新 `CasAuthenticationProvider` 以能够获取代理票据。 为此，请将
`Cas20ServiceTicketValidator` 替换为 `Cas20ProxyTicketValidator`。
`proxyCallbackUrl` 应设置为应用接收 PGT 的 URL。 最后，配置还应引用
`ProxyGrantingTicketStorage`，以便使用 PGT 获取代理票据。
下方展示了应做的配置更改示例：

``` xml
<bean id="casAuthenticationProvider"
    class="org.springframework.security.cas.authentication.CasAuthenticationProvider">
...
<property name="ticketValidator">
    <bean class="org.apereo.cas.client.validation.Cas20ProxyTicketValidator">
    <constructor-arg value="https://localhost:9443/cas"/>
        <property name="proxyCallbackUrl"
        value="https://localhost:8443/cas-sample/login/cas/proxyreceptor"/>
    <property name="proxyGrantingTicketStorage" ref="pgtStorage"/>
    </bean>
</property>
</bean>
```

最后一步是更新 `CasAuthenticationFilter` 以接受 PGT 并将其存储在
`ProxyGrantingTicketStorage` 中。 重要的是 `proxyReceptorUrl` 必须与
`Cas20ProxyTicketValidator` 的 `proxyCallbackUrl` 匹配。 示例配置如下：

``` xml
<bean id="casFilter"
        class="org.springframework.security.cas.web.CasAuthenticationFilter">
    ...
    <property name="proxyGrantingTicketStorage" ref="pgtStorage"/>
    <property name="proxyReceptorUrl" value="/login/cas/proxyreceptor"/>
</bean>
```

### 使用代理票据调用无状态服务 {#cas-pt-client-sample}

现在 Spring Security 已经能够获取
PGT，您可以使用它创建代理票据，进而用于向无状态服务认证。 CAS
[示例应用](samples.xml#samples) 在 `ProxyTicketSampleServlet`
中包含一个工作示例。 代码示例如下：

::: informalexample

Java

:   ``` java
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    // NOTE: The CasAuthenticationToken can also be obtained using
    // SecurityContextHolder.getContext().getAuthentication()
    final CasAuthenticationToken token = (CasAuthenticationToken) request.getUserPrincipal();
    // proxyTicket could be reused to make calls to the CAS service even if the
    // target url differs
    final String proxyTicket = token.getAssertion().getPrincipal().getProxyTicketFor(targetUrl);

    // Make a remote call using the proxy ticket
    final String serviceUrl = targetUrl+"?ticket="+URLEncoder.encode(proxyTicket, "UTF-8");
    String proxyResponse = CommonUtils.getResponseFromServer(serviceUrl, "UTF-8");
    ...
    }
    ```

Kotlin

:   ``` kotlin
    protected fun doGet(request: HttpServletRequest, response: HttpServletResponse?) {
        // NOTE: The CasAuthenticationToken can also be obtained using
        // SecurityContextHolder.getContext().getAuthentication()
        val token = request.userPrincipal as CasAuthenticationToken
        // proxyTicket could be reused to make calls to the CAS service even if the
        // target url differs
        val proxyTicket = token.assertion.principal.getProxyTicketFor(targetUrl)

        // Make a remote call using the proxy ticket
        val serviceUrl: String = targetUrl + "?ticket=" + URLEncoder.encode(proxyTicket, "UTF-8")
        val proxyResponse = CommonUtils.getResponseFromServer(serviceUrl, "UTF-8")
    }
    ```
:::

## 代理票据认证 {#cas-pt}

`CasAuthenticationProvider` 区分有状态和无状态客户端。
有状态客户端是指任何提交到 `CasAuthenticationFilter` 的
`filterProcessesUrl` 的请求。 无状态客户端是指在 `filterProcessesUrl`
以外的 URL 上向 `CasAuthenticationFilter` 提交认证请求的客户端。

由于远程调用协议无法在 `HttpSession`
上下文中呈现自身，因此不可能依赖于在请求之间将安全上下文存储在会话中的默认做法。
此外，由于 CAS 服务器在票据被 `TicketValidator`
验证后会使其失效，因此在后续请求中重复使用相同的代理票据将不起作用。

一个明显的选项是完全不为远程协议客户端使用 CAS。 但这将失去 CAS
的许多理想特性。 作为折中方案，`CasAuthenticationProvider` 使用
`StatelessTicketCache`。 它专用于使用主体等于
`CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER` 的无状态客户端。
具体过程是：`CasAuthenticationProvider` 将结果 `CasAuthenticationToken`
存储在 `StatelessTicketCache` 中，以代理票据为键。
因此，远程协议客户端可以重复提交相同的代理票据，而
`CasAuthenticationProvider` 无需每次都联系 CAS
服务器进行验证（首次请求除外）。
一旦认证成功，该代理票据可用于不同于原始目标服务的其他 URL。

本节在前述基础上扩展，以支持代理票据认证。
第一步是配置认证所有票据，如下所示：

``` xml
<bean id="serviceProperties"
    class="org.springframework.security.cas.ServiceProperties">
...
<property name="authenticateAllArtifacts" value="true"/>
</bean>
```

下一步是为 `CasAuthenticationFilter` 指定 `serviceProperties` 和
`authenticationDetailsSource`。 `serviceProperties` 属性指示
`CasAuthenticationFilter` 尝试认证所有票据，而不仅仅是出现在
`filterProcessesUrl` 上的票据。 `ServiceAuthenticationDetailsSource`
创建一个 `ServiceAuthenticationDetails`，确保在验证票据时使用当前
URL（基于 `HttpServletRequest`）作为服务 URL。 生成服务 URL
的方法可以通过注入自定义的 `AuthenticationDetailsSource` 返回自定义的
`ServiceAuthenticationDetails` 来定制。

``` xml
<bean id="casFilter"
    class="org.springframework.security.cas.web.CasAuthenticationFilter">
...
<property name="serviceProperties" ref="serviceProperties"/>
<property name="authenticationDetailsSource">
    <bean class=
    "org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource">
    <constructor-arg ref="serviceProperties"/>
    </bean>
</property>
</bean>
```

您还需要更新 `CasAuthenticationProvider` 以处理代理票据。 为此，请将
`Cas20ServiceTicketValidator` 替换为 `Cas20ProxyTicketValidator`。
您需要配置 `statelessTicketCache` 以及希望接受的代理列表。
以下是一个接受所有代理的配置示例：

``` xml
<bean id="casAuthenticationProvider"
    class="org.springframework.security.cas.authentication.CasAuthenticationProvider">
...
<property name="ticketValidator">
    <bean class="org.apereo.cas.client.validation.Cas20ProxyTicketValidator">
    <constructor-arg value="https://localhost:9443/cas"/>
    <property name="acceptAnyProxy" value="true"/>
    </bean>
</property>
<property name="statelessTicketCache">
    <bean class="org.springframework.security.cas.authentication.EhCacheBasedTicketCache">
    <property name="cache">
        <bean class="net.sf.ehcache.Cache"
            init-method="initialise" destroy-method="dispose">
        <constructor-arg value="casTickets"/>
        <constructor-arg value="50"/>
        <constructor-arg value="true"/>
        <constructor-arg value="false"/>
        <constructor-arg value="3600"/>
        <constructor-arg value="900"/>
        </bean>
    </property>
    </bean>
</property>
</bean>
```
