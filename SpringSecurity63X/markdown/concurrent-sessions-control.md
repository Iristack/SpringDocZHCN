与 [Servlet
的并发会话控制](servlet/authentication/session-management.xml#ns-concurrent-sessions)
类似，Spring Security
也支持在响应式（Reactive）应用中限制用户可同时拥有的会话数量。

当你在 Spring Security
中配置了并发会话控制后，它会通过拦截表单登录、[OAuth 2.0
登录](reactive/oauth2/login/index.xml) 和 HTTP Basic
认证等机制的认证成功处理流程来监控用户认证行为。具体来说，会话管理 DSL
会将
{security-api-url}org/springframework/security/web/server/authentication/ConcurrentSessionControlServerAuthenticationSuccessHandler.html\[ConcurrentSessionControlServerAuthenticationSuccessHandler\]
和
{security-api-url}org/springframework/security/web/server/authentication/RegisterSessionServerAuthenticationSuccessHandler.html\[RegisterSessionServerAuthenticationSuccessHandler\]
添加到认证过滤器所使用的 `ServerAuthenticationSuccessHandler` 列表中。

以下部分提供了如何配置并发会话控制的示例：

- [我希望限制用户可同时拥有的会话数量](#reactive-concurrent-sessions-control-limit)

- [当超过最大会话数时，我想自定义处理策略](#concurrent-sessions-control-custom-strategy)

- [我想知道如何指定一个
  `ReactiveSessionRegistry`](#reactive-concurrent-sessions-control-specify-session-registry)

- [我想查看使用并发会话控制的示例应用](#concurrent-sessions-control-sample)

- [我想了解如何对某些认证过滤器禁用该功能](#disabling-for-authentication-filters)

# 限制并发会话数量 {#reactive-concurrent-sessions-control-limit}

默认情况下，Spring Security
允许用户拥有任意数量的并发会话。要限制并发会话数，可以使用
`maximumSessions` DSL 方法：

:::: example
::: title
配置每个用户最多只能有一个会话
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(SessionLimit.of(1))
                )
            );
        return http.build();
    }

    @Bean
    ReactiveSessionRegistry reactiveSessionRegistry() {
        return new InMemoryReactiveSessionRegistry();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            // ...
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = SessionLimit.of(1)
                }
            }
        }
    }
    @Bean
    open fun reactiveSessionRegistry(): ReactiveSessionRegistry {
        return InMemoryReactiveSessionRegistry()
    }
    ```
::::

上述配置允许每个用户最多只有一个会话。类似地，你也可以使用
`SessionLimit#UNLIMITED` 常量来允许无限会话：

:::: example
::: title
配置无限制会话数量
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(SessionLimit.UNLIMITED))
            );
        return http.build();
    }

    @Bean
    ReactiveSessionRegistry reactiveSessionRegistry() {
        return new InMemoryReactiveSessionRegistry();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            // ...
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = SessionLimit.UNLIMITED
                }
            }
        }
    }
    @Bean
    open fun reactiveSessionRegistry(webSessionManager: WebSessionManager): ReactiveSessionRegistry {
        return InMemoryReactiveSessionRegistry()
    }
    ```
::::

由于 `maximumSessions` 方法接受的是 `SessionLimit`
接口，而该接口本身继承自
`Function<Authentication, Mono<Integer>>`，因此你可以基于用户的认证信息实现更复杂的逻辑来动态决定最大会话数：

:::: example
::: title
根据 `Authentication` 配置最大会话数
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(maxSessions()))
            );
        return http.build();
    }

    private SessionLimit maxSessions() {
        return (authentication) -> {
            if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_UNLIMITED_SESSIONS"))) {
                return Mono.empty(); // 对拥有 ROLE_UNLIMITED_SESSIONS 的用户允许无限会话
            }
            if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
                return Mono.just(2); // 管理员允许两个会话
            }
            return Mono.just(1); // 其他用户只允许一个会话
        };
    }

    @Bean
    ReactiveSessionRegistry reactiveSessionRegistry() {
        return new InMemoryReactiveSessionRegistry();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            // ...
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = maxSessions()
                }
            }
        }
    }

    fun maxSessions(): SessionLimit {
        return { authentication ->
            if (authentication.authorities.contains(SimpleGrantedAuthority("ROLE_UNLIMITED_SESSIONS"))) Mono.empty()
            else if (authentication.authorities.contains(SimpleGrantedAuthority("ROLE_ADMIN"))) Mono.just(2)
            else Mono.just(1)
        }
    }

    @Bean
    open fun reactiveSessionRegistry(): ReactiveSessionRegistry {
        return InMemoryReactiveSessionRegistry()
    }
    ```
::::

当用户超出最大会话数时，默认行为是使最近最少使用的会话失效。如果你想更改此行为，请参阅
[自定义超过最大会话数时的处理策略](#concurrent-sessions-control-custom-strategy)。

:::: important
::: title
:::

并发会话管理无法感知你可能通过 [OAuth 2
登录](reactive/oauth2/login/index.xml) 使用的身份提供者（Identity
Provider）上是否还存在其他会话。如果你也需要在身份提供者端注销会话，则必须
[提供自己的 `ServerMaximumSessionsExceededHandler`
实现](#concurrent-sessions-control-custom-strategy)。
::::

# 处理超过最大会话数的情况 {#concurrent-sessions-control-custom-strategy}

默认情况下，当用户超过最大会话数时，系统会使用
{security-api-url}org/springframework/security/web/server/authentication/session/InvalidateLeastUsedMaximumSessionsExceededHandler.html\[InvalidateLeastUsedMaximumSessionsExceededHandler\]
来使最近最少使用的会话失效。

Spring Security
还提供了另一个实现：{security-api-url}org/springframework/security/web/server/authentication/session/PreventLoginMaximumSessionsExceededHandler.html\[PreventLoginMaximumSessionsExceededHandler\]，它会阻止用户创建新会话。如果你希望使用自定义策略，可以提供一个不同的
{security-api-url}org/springframework/security/web/server/authentication/session/ServerMaximumSessionsExceededHandler.html\[ServerMaximumSessionsExceededHandler\]
实现。

:::: example
::: title
配置 maximumSessionsExceededHandler
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(SessionLimit.of(1))
                    .maximumSessionsExceededHandler(new PreventLoginMaximumSessionsExceededHandler())
                )
            );
        return http.build();
    }

    @Bean
    ReactiveSessionRegistry reactiveSessionRegistry() {
        return new InMemoryReactiveSessionRegistry();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            // ...
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = SessionLimit.of(1)
                    maximumSessionsExceededHandler = PreventLoginMaximumSessionsExceededHandler()
                }
            }
        }
    }

    @Bean
    open fun reactiveSessionRegistry(): ReactiveSessionRegistry {
        return InMemoryReactiveSessionRegistry()
    }
    ```
::::

# 指定 `ReactiveSessionRegistry` {#reactive-concurrent-sessions-control-specify-session-registry}

为了跟踪用户的会话，Spring Security 使用
{security-api-url}org/springframework/security/core/session/ReactiveSessionRegistry.html\[ReactiveSessionRegistry\]，每次用户登录时都会保存其会话信息。

Spring Security 提供了 `ReactiveSessionRegistry`
的默认实现：{security-api-url}org/springframework/security/core/session/InMemoryReactiveSessionRegistry.html\[InMemoryReactiveSessionRegistry\]。

要指定一个自定义的 `ReactiveSessionRegistry` 实现，你可以将其声明为
Bean：

:::: example
::: title
将 ReactiveSessionRegistry 声明为 Bean
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(SessionLimit.of(1))
                )
            );
        return http.build();
    }

    @Bean
    ReactiveSessionRegistry reactiveSessionRegistry() {
        return new MyReactiveSessionRegistry();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            // ...
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = SessionLimit.of(1)
                }
            }
        }
    }

    @Bean
    open fun reactiveSessionRegistry(): ReactiveSessionRegistry {
        return MyReactiveSessionRegistry()
    }
    ```
::::

或者，你也可以使用 `sessionRegistry` DSL 方法直接设置：

:::: example
::: title
使用 sessionRegistry DSL 方法指定 ReactiveSessionRegistry
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(SessionLimit.of(1))
                    .sessionRegistry(new MyReactiveSessionRegistry())
                )
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            // ...
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = SessionLimit.of(1)
                    sessionRegistry = MyReactiveSessionRegistry()
                }
            }
        }
    }
    ```
::::

# 手动注销已注册用户的会话 {#reactive-concurrent-sessions-control-manually-invalidating-sessions}

有时，能够手动注销某个用户的所有或部分会话是非常有用的。例如，当用户更改密码时，你可能希望注销其所有会话，强制其重新登录。为此，你可以使用
`ReactiveSessionRegistry` Bean 获取该用户的所有会话，将其注销，并从
`WebSessionStore` 中移除：

:::: example
::: title
使用 ReactiveSessionRegistry 手动注销会话
:::

Java

:   ``` java
    public class SessionControl {
        private final ReactiveSessionRegistry reactiveSessionRegistry;

        private final WebSessionStore webSessionStore;

        public Mono<Void> invalidateSessions(String username) {
            return this.reactiveSessionRegistry.getAllSessions(username)
                .flatMap((session) -> session.invalidate().thenReturn(session))
                .flatMap((session) -> this.webSessionStore.removeSession(session.getSessionId()))
                .then();
        }
    }
    ```
::::

# 对某些认证过滤器禁用并发会话控制 {#disabling-for-authentication-filters}

默认情况下，只要表单登录、OAuth 2.0 登录和 HTTP Basic
认证没有显式指定自己的 `ServerAuthenticationSuccessHandler`，Spring
Security
就会自动为它们配置并发会话控制。例如，以下配置将禁用表单登录的并发会话控制：

:::: example
::: title
对表单登录禁用并发会话控制
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .formLogin((login) -> login
                .authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/"))
            )
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(SessionLimit.of(1))
                )
            );
        return http.build();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            // ...
            formLogin {
                authenticationSuccessHandler = RedirectServerAuthenticationSuccessHandler("/")
            }
            sessionManagement {
                sessionConcurrency {
                    maximumSessions = SessionLimit.of(1)
                }
            }
        }
    }
    ```
::::

## 在不关闭并发会话控制的前提下添加额外的成功处理器 {#_在不关闭并发会话控制的前提下添加额外的成功处理器}

你还可以向认证过滤器使用的处理器列表中添加额外的
`ServerAuthenticationSuccessHandler`
实例，而不影响并发会话控制的功能。为此，可以使用
`authenticationSuccessHandler(Consumer<List<ServerAuthenticationSuccessHandler>>)`
方法：

:::: example
::: title
添加额外的处理器
:::

Java

:   ``` java
    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http
            // ...
            .formLogin((login) -> login
                .authenticationSuccessHandler((handlers) -> handlers.add(new MyAuthenticationSuccessHandler()))
            )
            .sessionManagement((sessions) -> sessions
                .concurrentSessions((concurrency) -> concurrency
                    .maximumSessions(SessionLimit.of(1))
                )
            );
        return http.build();
    }
    ```
::::

# 查看示例应用 {#concurrent-sessions-control-sample}

你可以在此查看完整的
{gh-samples-url}/reactive/webflux/java/session-management/maximum-sessions\[示例应用\]。
