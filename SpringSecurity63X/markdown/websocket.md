Spring Security 4 添加了对 [Spring WebSocket
支持](https://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html)
的保护功能。 本节介绍如何使用 Spring Security 的 WebSocket 支持。

:::: sidebar
::: title
直接支持 JSR-356
:::

Spring Security 不提供对 JSR-356 的直接支持，因为这样做提供的价值很小。
这是因为消息格式未知，而 Spring 无法对未知格式进行有效安全防护。
此外，JSR-356 没有提供拦截消息的机制，因此安全性实现会变得侵入性强。
::::

# WebSocket 认证 {#websocket-authentication}

WebSocket 复用在建立连接时 HTTP 请求中已有的认证信息。 这意味着
`HttpServletRequest` 上的 `Principal` 会被传递给 WebSocket。
如果你使用的是 Spring Security，`HttpServletRequest` 上的 `Principal`
会自动被覆盖。

更具体地说，要确保用户已成功登录你的 WebSocket 应用程序，只需配置好
Spring Security 来认证基于 HTTP 的 Web 应用即可。

# WebSocket 授权 {#websocket-authorization}

Spring Security 4.0 引入了通过 Spring Messaging 抽象层实现的 WebSocket
授权支持。

在 Spring Security 5.8 中，该支持已更新为使用 `AuthorizationManager`
API。

要通过 Java 配置启用授权，请包含 `@EnableWebSocketSecurity`
注解，并发布一个 `AuthorizationManager<Message<?>>` Bean；或者在
[XML](servlet/appendix/namespace/websocket.xml#nsa-websocket-security)
中使用 `use-authorization-manager` 属性。 一种实现方式是使用
`AuthorizationManagerMessageMatcherRegistry`
指定端点匹配模式，如下所示：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSocketSecurity  
    public class WebSocketSecurityConfig {

        @Bean
        AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
            messages
                    .simpDestMatchers("/user/**").hasRole("USER") 

            return messages.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSocketSecurity  
    open class WebSocketSecurityConfig {  
        @Bean
        fun messageAuthorizationManager(messages: MessageMatcherDelegatingAuthorizationManager.Builder): AuthorizationManager<Message<*>> {
            messages.simpDestMatchers("/user/**").hasRole("USER") 
            return messages.build()
        }
    }
    ```

Xml

:   ``` xml
    <websocket-message-broker use-authorization-manager="true">  
        <intercept-message pattern="/user/**" access="hasRole('USER')"/> 
    </websocket-message-broker>
    ```
:::

- 所有入站 CONNECT 消息都需要有效的 CSRF 令牌，以强制执行
  [同源策略](#websocket-sameorigin)。

- 对于任何入站请求，用户的 `SecurityContextHolder` 将根据 `simpUser`
  消息头属性填充。

- 我们的消息需要正确的授权。具体来说，所有以 `/user/`
  开头的入站消息都要求具有 `ROLE_USER` 角色。更多授权细节请参见
  [WebSocket 授权](#websocket-authorization)

## 自定义授权 {#_自定义授权}

使用 `AuthorizationManager` 时，自定义非常简单。
例如，你可以发布一个使用 `AuthorityAuthorizationManager`
要求所有消息都具备 \"USER\" 角色的 `AuthorizationManager`，如下所示：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSocketSecurity  
    public class WebSocketSecurityConfig {

        @Bean
        AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
            return AuthorityAuthorizationManager.hasRole("USER");
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSocketSecurity  
    open class WebSocketSecurityConfig {
        @Bean
        fun messageAuthorizationManager(messages: MessageMatcherDelegatingAuthorizationManager.Builder): AuthorizationManager<Message<*>> {
            return AuthorityAuthorizationManager.hasRole("USER") 
        }
    }
    ```

Xml

:   ``` xml
    <bean id="authorizationManager" class="org.example.MyAuthorizationManager"/>

    <websocket-message-broker authorization-manager-ref="myAuthorizationManager"/>
    ```
:::

还有多种方法可以进一步匹配消息，下面是一个更复杂的示例：

::: informalexample

Java

:   ``` java
    @Configuration
    public class WebSocketSecurityConfig {

        @Bean
        public AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
            messages
                    .nullDestMatcher().authenticated() 
                    .simpSubscribeDestMatchers("/user/queue/errors").permitAll() 
                    .simpDestMatchers("/app/**").hasRole("USER") 
                    .simpSubscribeDestMatchers("/user/**", "/topic/friends/*").hasRole("USER") 
                    .simpTypeMatchers(MESSAGE, SUBSCRIBE).denyAll() 
                    .anyMessage().denyAll(); 

            return messages.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    open class WebSocketSecurityConfig {
        fun messageAuthorizationManager(messages: MessageMatcherDelegatingAuthorizationManager.Builder): AuthorizationManager<Message<*>> {
            messages
                .nullDestMatcher().authenticated() 
                .simpSubscribeDestMatchers("/user/queue/errors").permitAll() 
                .simpDestMatchers("/app/**").hasRole("USER") 
                .simpSubscribeDestMatchers("/user/**", "/topic/friends/*").hasRole("USER") 
                .simpTypeMatchers(MESSAGE, SUBSCRIBE).denyAll() 
                .anyMessage().denyAll() 

            return messages.build();
        }
    }
    ```

Xml

:   ``` xml
    <websocket-message-broker use-authorization-manager="true">
        
        <intercept-message type="CONNECT" access="permitAll" />
        <intercept-message type="UNSUBSCRIBE" access="permitAll" />
        <intercept-message type="DISCONNECT" access="permitAll" />

        <intercept-message pattern="/user/queue/errors" type="SUBSCRIBE" access="permitAll" /> 
        <intercept-message pattern="/app/**" access="hasRole('USER')" />      

        
        <intercept-message pattern="/user/**" type="SUBSCRIBE" access="hasRole('USER')" />
        <intercept-message pattern="/topic/friends/*" type="SUBSCRIBE" access="hasRole('USER')" />

        
        <intercept-message type="MESSAGE" access="denyAll" />
        <intercept-message type="SUBSCRIBE" access="denyAll" />

        <intercept-message pattern="/**" access="denyAll" /> 
    </websocket-message-broker>
    ```
:::

上述配置将确保：

- 任何没有目标地址的消息（即非 MESSAGE 或 SUBSCRIBE
  类型）都需要用户经过身份验证。

- 任何人都可以订阅 `/user/queue/errors`。

- 目标地址以 `/app/` 开头的所有消息都需要用户拥有 `ROLE_USER` 角色。

- 类型为 SUBSCRIBE 且目标地址以 `/user/` 或 `/topic/friends/`
  开头的消息都需要 `ROLE_USER`。

- 其他所有 MESSAGE 或 SUBSCRIBE 类型的消息都被拒绝。由于第 6
  条的存在，这一步其实可省略，但它展示了如何按特定消息类型进行匹配。

- 其余所有消息均被拒绝。这是个好习惯，以防遗漏某些消息。

## 迁移 SpEL 表达式 {#migrating-spel-expressions}

如果你从旧版本的 Spring Security 升级而来，你可能在目标匹配器中使用了
SpEL 表达式。 建议将其替换为 `AuthorizationManager`
的具体实现，因为这样更容易独立测试。

不过，为了简化迁移过程，你也可以使用类似以下的类：

``` java
public final class MessageExpressionAuthorizationManager implements AuthorizationManager<MessageAuthorizationContext<?>> {

    private SecurityExpressionHandler<Message<?>> expressionHandler = new DefaultMessageSecurityExpressionHandler();

    private Expression expression;

    public MessageExpressionAuthorizationManager(String expressionString) {
        Assert.hasText(expressionString, "expressionString cannot be empty");
        this.expression = this.expressionHandler.getExpressionParser().parseExpression(expressionString);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MessageAuthorizationContext<?> context) {
        EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, context.getMessage());
        boolean granted = ExpressionUtils.evaluateAsBoolean(this.expression, ctx);
        return new ExpressionAuthorizationDecision(granted, this.expression);
    }

}
```

然后为无法立即迁移的每个匹配器指定一个实例：

::: informalexample

Java

:   ``` java
    @Configuration
    public class WebSocketSecurityConfig {

        @Bean
        public AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
            messages
                    // ...
                    .simpSubscribeDestMatchers("/topic/friends/{friend}").access(new MessageExpressionAuthorizationManager("#friends == 'john"));
                    // ...

            return messages.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    open class WebSocketSecurityConfig {
        fun messageAuthorizationManager(messages: MessageMatcherDelegatingAuthorizationManager.Builder): AuthorizationManager<Message<?> {
            messages
                // ..
                .simpSubscribeDestMatchers("/topic/friends/{friends}").access(MessageExpressionAuthorizationManager("#friends == 'john"))
                // ...

            return messages.build()
        }
    }
    ```
:::

## WebSocket 授权注意事项 {#websocket-authorization-notes}

要正确保护你的应用程序，你需要理解 Spring 的 WebSocket 支持。

### 基于消息类型的 WebSocket 授权 {#websocket-authorization-notes-messagetypes}

你需要了解 `SUBSCRIBE` 和 `MESSAGE` 类型消息之间的区别及其工作原理。

考虑一个聊天应用：

- 系统可以通过向 `/topic/system/notifications` 发送一条 `MESSAGE`
  向所有用户发送通知。

- 客户端可以通过 `SUBSCRIBE` 到 `/topic/system/notifications`
  来接收这些通知。

我们希望客户端能够 `SUBSCRIBE` 到
`/topic/system/notifications`，但不希望允许它们向该目的地发送
`MESSAGE`。 如果允许向 `/topic/system/notifications` 发送
`MESSAGE`，客户端就可以直接向该端点发送消息并冒充系统。

通常情况下，应用程序会拒绝任何发往以
[代理前缀](https://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html#websocket-stomp)（如
`/topic/` 或 `/queue/`）开头的目的地的 `MESSAGE`。

### 基于目标地址的 WebSocket 授权 {#websocket-authorization-notes-destinations}

你还应了解目标地址是如何转换的。

继续以聊天应用为例：

- 用户可通过向 `/app/chat` 发送消息来向特定用户发送消息。

- 应用程序收到消息后，会检查 `from`
  字段是否等于当前用户（不能信任客户端输入）。

- 然后应用程序调用
  `SimpMessageSendingOperations.convertAndSendToUser("toUser", "/queue/messages", message)`
  将消息发送给接收者。

- 消息最终被转为 `/queue/user/messages-<sessionid>` 的目标地址。

在这个聊天应用中，我们希望客户端能监听 `/user/queue`，它会被映射为
`/queue/user/messages-<sessionid>`。 但我们不希望客户端能监听
`/queue/*`，否则客户端可以看到所有用户的消息。

通常，应用程序会拒绝任何发往以
[代理前缀](https://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html#websocket-stomp)（如
`/topic/` 或 `/queue/`）开头的消息的 `SUBSCRIBE` 请求。
我们可以为此设置例外情况，比如：

## 出站消息 {#websocket-authorization-notes-outbound}

Spring 框架参考文档中有一节名为
[\"消息流\"](https://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html#websocket-stomp-message-flow)，描述了消息在系统中的流动方式。
请注意，Spring Security 仅保护 `clientInboundChannel`，而不尝试保护
`clientOutboundChannel`。

最主要的原因是性能：每条入站消息通常对应多条出站消息。
与其保护出站消息，我们更推荐通过控制对端点的订阅权限来进行保护。

# 强制同源策略 {#websocket-sameorigin}

注意：浏览器不会对 WebSocket 连接强制执行
[同源策略](https://en.wikipedia.org/wiki/Same-origin_policy)。这是一个极其重要的安全考量。

## 为何需要同源策略？ {#websocket-sameorigin-why}

设想以下场景： 用户访问 `bank.com`
并登录账户。随后在同一浏览器打开另一个标签页访问 `evil.com`。
同源策略确保 `evil.com` 无法读取或写入 `bank.com` 的数据。

但对于 WebSocket，同源策略不生效。 实际上，除非 `bank.com`
明确禁止，否则 `evil.com` 可代表用户读写数据。 这意味着用户能通过
WebSocket 执行的操作（如转账），`evil.com` 也能以该用户身份完成。

由于 SockJS 试图模拟 WebSocket，它同样绕过了同源策略。
这意味着开发者在使用 SockJS 时必须显式防止外部域的访问。

## Spring WebSocket 允许的来源 {#websocket-sameorigin-spring}

幸运的是，自 Spring 4.1.5 起，Spring 的 WebSocket 和 SockJS
支持默认限制只能访问
[当前域](https://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html#websocket-server-allowed-origins)。
Spring Security 在此基础上增加了一层保护，实现了
[纵深防御](https://en.wikipedia.org/wiki/Defence_in_depth_(non-military)#Information_security)。

## 在 STOMP 头部添加 CSRF 令牌 {#websocket-sameorigin-csrf}

默认情况下，Spring Security 要求任何 `CONNECT` 消息类型中包含 [CSRF
令牌](features/exploits/csrf.xml#csrf)。 这确保只有能获取到 CSRF
令牌的站点才能建立连接。 由于只有 **同源站点** 才能访问 CSRF
令牌，因此外部域无法建立连接。

通常我们需要将 CSRF 令牌放入 HTTP 头或参数中。 但 SockJS
不支持这些选项，因此我们必须将令牌放在 STOMP 消息头中。

应用程序可通过请求属性 `_csrf` 获取 CSRF 令牌。 例如，以下代码可在 JSP
中访问 `CsrfToken`：

``` javascript
var headerName = "${_csrf.headerName}";
var token = "${_csrf.token}";
```

若使用静态 HTML，可通过 REST 接口暴露 `CsrfToken`。 例如，以下代码将在
`/csrf` URL 上暴露 `CsrfToken`：

::: informalexample

Java

:   ``` java
    @RestController
    public class CsrfController {

        @RequestMapping("/csrf")
        public CsrfToken csrf(CsrfToken token) {
            return token;
        }
    }
    ```

Kotlin

:   ``` kotlin
    @RestController
    class CsrfController {
        @RequestMapping("/csrf")
        fun csrf(token: CsrfToken): CsrfToken {
            return token
        }
    }
    ```
:::

JavaScript 可以调用此 REST 接口，并使用响应填充 `headerName` 和
`token`。

现在我们可以在 Stomp 客户端中包含该令牌：

``` javascript
...
var headers = {};
headers[headerName] = token;
stompClient.connect(headers, function(frame) {
  ...

})
```

## 禁用 WebSocket 中的 CSRF {#websocket-sameorigin-disable}

:::: note
::: title
:::

当前使用 `@EnableWebSocketSecurity` 时，CSRF
不可配置，但未来版本可能会加入此功能。
::::

要禁用 CSRF，可以不使用 `@EnableWebSocketSecurity`，而是使用 XML
配置或手动添加 Spring Security 组件，如下所示：

::: informalexample

Java

:   ``` java
    @Configuration
    public class WebSocketSecurityConfig implements WebSocketMessageBrokerConfigurer {

        @Override
        public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
            argumentResolvers.add(new AuthenticationPrincipalArgumentResolver());
        }

        @Override
        public void configureClientInboundChannel(ChannelRegistration registration) {
            AuthorizationManager<Message<?>> myAuthorizationRules = AuthenticatedAuthorizationManager.authenticated();
            AuthorizationChannelInterceptor authz = new AuthorizationChannelInterceptor(myAuthorizationRules);
            AuthorizationEventPublisher publisher = new SpringAuthorizationEventPublisher(this.context);
            authz.setAuthorizationEventPublisher(publisher);
            registration.interceptors(new SecurityContextChannelInterceptor(), authz);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    open class WebSocketSecurityConfig : WebSocketMessageBrokerConfigurer {
        @Override
        override fun addArgumentResolvers(argumentResolvers: List<HandlerMethodArgumentResolver>) {
            argumentResolvers.add(AuthenticationPrincipalArgumentResolver())
        }

        @Override
        override fun configureClientInboundChannel(registration: ChannelRegistration) {
            var myAuthorizationRules: AuthorizationManager<Message<*>> = AuthenticatedAuthorizationManager.authenticated()
            var authz: AuthorizationChannelInterceptor = AuthorizationChannelInterceptor(myAuthorizationRules)
            var publisher: AuthorizationEventPublisher = SpringAuthorizationEventPublisher(this.context)
            authz.setAuthorizationEventPublisher(publisher)
            registration.interceptors(SecurityContextChannelInterceptor(), authz)
        }
    }
    ```

Xml

:   ``` xml
    <websocket-message-broker use-authorization-manager="true" same-origin-disabled="true">
        <intercept-message pattern="/**" access="authenticated"/>
    </websocket-message-broker>
    ```
:::

另一方面，如果你正在使用 [旧版
`AbstractSecurityWebSocketMessageBrokerConfigurer`](#legacy-websocket-configuration)
并希望允许其他域访问你的站点，可以禁用 Spring Security 的保护。例如，在
Java 配置中可以这样写：

::: informalexample

Java

:   ``` java
    @Configuration
    public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

        ...

        @Override
        protected boolean sameOriginDisabled() {
            return true;
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    open class WebSocketSecurityConfig : AbstractSecurityWebSocketMessageBrokerConfigurer() {

        // ...

        override fun sameOriginDisabled(): Boolean {
            return true
        }
    }
    ```
:::

## 自定义表达式处理器 {#websocket-expression-handler}

有时你可能希望自定义 `intercept-message` XML 元素中定义的 `access`
表达式的处理方式。 为此，你可以创建一个
`SecurityExpressionHandler<MessageAuthorizationContext<?>>`
类型的类，并在 XML 中引用它，如下所示：

``` xml
<websocket-message-broker use-authorization-manager="true">
    <expression-handler ref="myRef"/>
    ...
</websocket-message-broker>

<b:bean ref="myRef" class="org.springframework.security.messaging.access.expression.MessageAuthorizationContextSecurityExpressionHandler"/>
```

如果你正在从实现 `SecurityExpressionHandler<Message<?>>` 的旧版
`websocket-message-broker` 迁移，你可以： 1. 额外实现
`createEvaluationContext(Supplier, Message)` 方法； 2. 然后将其包装在
`MessageAuthorizationContextSecurityExpressionHandler` 中，如下所示：

``` xml
<websocket-message-broker use-authorization-manager="true">
    <expression-handler ref="myRef"/>
    ...
</websocket-message-broker>

<b:bean ref="myRef" class="org.springframework.security.messaging.access.expression.MessageAuthorizationContextSecurityExpressionHandler">
    <b:constructor-arg>
        <b:bean class="org.example.MyLegacyExpressionHandler"/>
    </b:constructor-arg>
</b:bean>
```

# 使用 SockJS {#websocket-sockjs}

[SockJS](https://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html#websocket-fallback)
提供回退传输机制以支持较老的浏览器。
使用回退选项时，我们需要放宽一些安全限制，以便 SockJS 与 Spring Security
正常协作。

## SockJS 与 frame-options {#websocket-sockjs-sameorigin}

SockJS 可能使用依赖 iframe 的
[传输方式](https://github.com/sockjs/sockjs-client/tree/v0.3.4)。
默认情况下，Spring Security 的
[拒绝](features/exploits/headers.xml#headers-frame-options) 页面被嵌套在
frame 中，以防止点击劫持攻击。 为了让基于 iframe 的 SockJS
传输正常工作，我们需要配置 Spring Security 允许同源嵌套内容。

你可以使用
[frame-options](servlet/appendix/namespace/http.xml#nsa-frame-options)
元素自定义 `X-Frame-Options`。 例如，以下配置指示 Spring Security 使用
`X-Frame-Options: SAMEORIGIN`，允许同域内的 iframe 嵌套：

``` xml
<http>
    <!-- ... -->

    <headers>
        <frame-options
          policy="SAMEORIGIN" />
    </headers>
</http>
```

同样，你也可以通过 Java 配置来自定义 frame 选项，使其使用同源策略：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class WebSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                // ...
                .headers(headers -> headers
                    .frameOptions(frameOptions -> frameOptions
                         .sameOrigin()
                    )
            );
            return http.build();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    open class WebSecurityConfig {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                // ...
                headers {
                    frameOptions {
                        sameOrigin = true
                    }
                }
            }
            return http.build()
        }
    }
    ```
:::

## SockJS 与放宽 CSRF 限制 {#websocket-sockjs-csrf}

SockJS 在基于 HTTP 的传输中会对 CONNECT 消息使用 POST 请求。
通常我们需要将 CSRF 令牌放在 HTTP 头或参数中。 但 SockJS
不支持这些选项，因此我们必须像 [在 STOMP 头部添加 CSRF
令牌](#websocket-sameorigin-csrf) 中所述那样将令牌放在 STOMP 消息头中。

这也意味着我们需要适当放宽 Web 层的 CSRF 保护。
具体而言，我们希望仅对连接 URL 禁用 CSRF 保护，而不是对所有 URL
禁用，否则会使网站面临 CSRF 攻击风险。

我们可以通过提供一个 CSRF `RequestMatcher` 来轻松实现这一点。Java
配置对此提供了便利。 例如，如果我们的 STOMP 端点是 `/chat`，则可以仅对以
`/chat/` 开头的 URL 禁用 CSRF 保护，配置如下：

::: informalexample

Java

:   ``` java
    @Configuration
    @EnableWebSecurity
    public class WebSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .csrf(csrf -> csrf
                    // 忽略我们的 STOMP 端点，因为它们由 STOMP 头保护
                    .ignoringRequestMatchers("/chat/**")
                )
                .headers(headers -> headers
                    // 允许同源嵌套页面以支持 iframe 形式的 SockJS
                    .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                    )
                )
                .authorizeHttpRequests(authorize -> authorize
                    ...
                )
                ...
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableWebSecurity
    open class WebSecurityConfig {
        @Bean
        open fun filterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                csrf {
                    ignoringRequestMatchers("/chat/**")
                }
                headers {
                    frameOptions {
                        sameOrigin = true
                    }
                }
                authorizeRequests {
                    // ...
                }
                // ...
            }
        }
    }
    ```
:::

如果使用基于 XML 的配置，可以使用
[csrf@request-matcher-ref](servlet/appendix/namespace/http.xml#nsa-csrf-request-matcher-ref)。

``` xml
<http ...>
    <csrf request-matcher-ref="csrfMatcher"/>

    <headers>
        <frame-options policy="SAMEORIGIN"/>
    </headers>

    ...
</http>

<b:bean id="csrfMatcher"
    class="AndRequestMatcher">
    <b:constructor-arg value="#{T(org.springframework.security.web.csrf.CsrfFilter).DEFAULT_CSRF_MATCHER}"/>
    <b:constructor-arg>
        <b:bean class="org.springframework.security.web.util.matcher.NegatedRequestMatcher">
          <b:bean class="org.springframework.security.web.util.matcher.AntPathRequestMatcher">
            <b:constructor-arg value="/chat/**"/>
          </b:bean>
        </b:bean>
    </b:constructor-arg>
</b:bean>
```

# 旧版 WebSocket 配置 {#legacy-websocket-configuration}

在 Spring Security 5.8 之前，使用 Java 配置消息授权的方式是继承
`AbstractSecurityWebSocketMessageBrokerConfigurer` 并配置
`MessageSecurityMetadataSourceRegistry`。例如：

::: informalexample

Java

:   ``` java
    @Configuration
    public class WebSocketSecurityConfig
          extends AbstractSecurityWebSocketMessageBrokerConfigurer {  

        protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
            messages
                    .simpDestMatchers("/user/**").authenticated() 
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    open class WebSocketSecurityConfig : AbstractSecurityWebSocketMessageBrokerConfigurer() {  
        override fun configureInbound(messages: MessageSecurityMetadataSourceRegistry) {
            messages.simpDestMatchers("/user/**").authenticated() 
        }
    }
    ```
:::

该配置将确保：

- 所有入站 CONNECT 消息都需要有效的 CSRF 令牌，以强制执行
  [同源策略](#websocket-sameorigin)。

- 对于任何入站请求，`SecurityContextHolder` 将根据 `simpUser`
  消息头属性填充用户信息。

- 我们的消息需要正确的授权。具体来说，任何以 `/user/`
  开头的入站消息都要求 `ROLE_USER`。更多授权细节请参见 [WebSocket
  授权](#websocket-authorization)

当你有一个自定义的 `SecurityExpressionHandler` 继承自
`AbstractSecurityExpressionHandler` 并重写了
`createEvaluationContextInternal` 或 `createSecurityExpressionRoot`
时，使用旧版配置是有帮助的。 新的 `AuthorizationManager` API 为了延迟
`Authorization` 查找，在评估表达式时不会调用这些方法。

如果你使用 XML 配置，可以通过不使用 `use-authorization-manager`
元素或将该属性设为 `false` 来使用旧版 API。
