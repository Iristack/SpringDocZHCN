Spring Security 开箱即用地与 Spring Observability
集成，支持追踪（tracing）；同时也可以轻松配置以收集指标（metrics）。

# 追踪（Tracing） {#observability-tracing}

当存在 `ObservationRegistry` Bean 时，Spring Security
会为以下组件创建追踪信息：

- 过滤器链（filter chain）

- `AuthenticationManager`

- `AuthorizationManager`

## Boot 集成 {#observability-tracing-boot}

例如，考虑一个简单的 Spring Boot 应用程序：

::: informalexample

Java

:   ``` java
    @SpringBootApplication
    public class MyApplication {
        @Bean
        public UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(
                    User.withDefaultPasswordEncoder()
                            .username("user")
                            .password("password")
                            .authorities("app")
                            .build()
            );
        }

        @Bean
        ObservationRegistryCustomizer<ObservationRegistry> addTextHandler() {
            return (registry) -> registry.observationConfig().observationHandler(new ObservationTextPublisher());
        }

        public static void main(String[] args) {
            SpringApplication.run(ListenerSamplesApplication.class, args);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @SpringBootApplication
    class MyApplication {
        @Bean
        fun userDetailsService(): UserDetailsService {
            InMemoryUserDetailsManager(
                    User.withDefaultPasswordEncoder()
                            .username("user")
                            .password("password")
                            .authorities("app")
                            .build()
            );
        }

        @Bean
        fun addTextHandler(): ObservationRegistryCustomizer<ObservationRegistry> {
            return registry: ObservationRegistry -> registry.observationConfig()
                    .observationHandler(ObservationTextPublisher());
        }

        fun main(args: Array<String>) {
            runApplication<MyApplication>(*args)
        }
    }
    ```
:::

以及一个对应的请求：

``` bash
?> http -a user:password :8080
```

将产生如下输出（缩进已添加以便阅读）：

``` bash
START - name='http.server.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@687e16d1', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.001779024, duration(nanos)=1779024.0, startTimeNanos=91695917264958}']
    START - name='spring.security.http.chains', contextualName='spring.security.http.chains.before', error='null', lowCardinalityKeyValues=[chain.position='0', chain.size='17', filter.section='before'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@79f554a5', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=7.42147E-4, duration(nanos)=742147.0, startTimeNanos=91695947182029}']
    ... 省略部分内容 ...
    STOP - name='spring.security.http.chains', contextualName='spring.security.http.chains.before', error='null', lowCardinalityKeyValues=[chain.position='0', chain.size='17', filter.section='before'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@79f554a5', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.014771848, duration(nanos)=1.4771848E7, startTimeNanos=91695947182029}']
        START - name='spring.security.authentications', contextualName='null', error='null', lowCardinalityKeyValues=[authentication.failure.type='Optional', authentication.method='ProviderManager', authentication.request.type='UsernamePasswordAuthenticationToken'], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@4d4b2b56', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=7.09759E-4, duration(nanos)=709759.0, startTimeNanos=91696094477504}']
        ... 省略部分内容 ...
        STOP - name='spring.security.authentications', contextualName='null', error='null', lowCardinalityKeyValues=[authentication.failure.type='Optional', authentication.method='ProviderManager', authentication.request.type='UsernamePasswordAuthenticationToken', authentication.result.type='UsernamePasswordAuthenticationToken'], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@4d4b2b56', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.895141386, duration(nanos)=8.95141386E8, startTimeNanos=91696094477504}']
        START - name='spring.security.authorizations', contextualName='null', error='null', lowCardinalityKeyValues=[object.type='Servlet3SecurityContextHolderAwareRequestWrapper'], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@6d834cc7', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=3.0965E-4, duration(nanos)=309650.0, startTimeNanos=91697034893983}']
        ... 省略部分内容 ...
        STOP - name='spring.security.authorizations', contextualName='null', error='null', lowCardinalityKeyValues=[authorization.decision='true', object.type='Servlet3SecurityContextHolderAwareRequestWrapper'], highCardinalityKeyValues=[authentication.authorities='[app]', authorization.decision.details='AuthorizationDecision [granted=true]'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@6d834cc7', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.02084809, duration(nanos)=2.084809E7, startTimeNanos=91697034893983}']
        START - name='spring.security.http.secured.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@649c5ec3', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=2.67878E-4, duration(nanos)=267878.0, startTimeNanos=91697059819304}']
        ... 省略部分内容 ...
        STOP - name='spring.security.http.secured.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@649c5ec3', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.090753322, duration(nanos)=9.0753322E7, startTimeNanos=91697059819304}']
    START - name='spring.security.http.chains', contextualName='spring.security.http.chains.after', error='null', lowCardinalityKeyValues=[chain.position='0', chain.size='17', filter.section='after'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@47af8207', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=5.31832E-4, duration(nanos)=531832.0, startTimeNanos=91697152857268}']
    ... 省略部分内容 ...
    STOP - name='spring.security.http.chains', contextualName='spring.security.http.chains.after', error='null', lowCardinalityKeyValues=[chain.position='17', chain.size='17', current.filter.name='DisableEncodeUrlFilter', filter.section='after'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@47af8207', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.007689382, duration(nanos)=7689382.0, startTimeNanos=91697152857268}']
STOP - name='http.server.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@687e16d1', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=1.245858319, duration(nanos)=1.245858319E9, startTimeNanos=91695917264958}']
```

## 手动配置 {#observability-tracing-manual-configuration}

对于非 Spring Boot 应用程序，或需要覆盖现有 Boot
配置的情况，你可以自行发布 `ObservationRegistry` Bean，Spring Security
仍会自动使用它。

::: informalexample

Java

:   ``` java
    @SpringBootApplication
    public class MyApplication {
        @Bean
        public UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(
                    User.withDefaultPasswordEncoder()
                            .username("user")
                            .password("password")
                            .authorities("app")
                            .build()
            );
        }

        @Bean
        ObservationRegistry<ObservationRegistry> observationRegistry() {
            ObservationRegistry registry = ObservationRegistry.create();
            registry.observationConfig().observationHandler(new ObservationTextPublisher());
            return registry;
        }

        public static void main(String[] args) {
            SpringApplication.run(ListenerSamplesApplication.class, args);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @SpringBootApplication
    class MyApplication {
        @Bean
        fun userDetailsService(): UserDetailsService {
            InMemoryUserDetailsManager(
                    User.withDefaultPasswordEncoder()
                            .username("user")
                            .password("password")
                            .authorities("app")
                            .build()
            );
        }

        @Bean
        fun observationRegistry(): ObservationRegistry<ObservationRegistry> {
            val registry = ObservationRegistry.create()
            registry.observationConfig().observationHandler(ObservationTextPublisher())
            return registry
        }

        fun main(args: Array<String>) {
            runApplication<MyApplication>(*args)
        }
    }
    ```

Xml

:   ``` xml
    <sec:http auto-config="true" observation-registry-ref="ref">
        <sec:intercept-url pattern="/**" access="authenticated"/>
    </sec:http>

    <!-- 定义并配置 ObservationRegistry Bean -->
    ```
:::

### 禁用可观测性 {#observability-tracing-disable}

如果你不希望启用任何 Spring Security 的观测功能，在 Spring Boot
应用中可以注册一个 `ObservationRegistry.NOOP` 的 `@Bean`。
但请注意，这可能会关闭除 Spring Security 外的其他组件的观测功能。

更推荐的方式是通过 `ObservationPredicate` 来修改现有的
`ObservationRegistry`，例如：

::: informalexample

Java

:   ``` java
    @Bean
    ObservationRegistryCustomizer<ObservationRegistry> noSpringSecurityObservations() {
        ObservationPredicate predicate = (name, context) -> !name.startsWith("spring.security.");
        return (registry) -> registry.observationConfig().observationPredicate(predicate);
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun noSpringSecurityObservations(): ObservationRegistryCustomizer<ObservationRegistry> {
        val predicate = ObservationPredicate { name: String, _: Observation.Context ->
            !name.startsWith("spring.security.")
        }
        return ObservationRegistryCustomizer { registry ->
            registry.observationConfig().observationPredicate(predicate)
        }
    }
    ```
:::

:::: tip
::: title
:::

XML 配置方式目前不支持禁用观测功能。 若要避免启用，只需不要设置
`observation-registry-ref` 属性即可。
::::

## 追踪范围列表 {#observability-tracing-listing}

Spring Security 在每个请求中跟踪以下跨度（spans）：

1.  `spring.security.http.requests` ---
    包裹整个过滤器链（包括请求）的跨度

2.  `spring.security.http.chains.before` ---
    包裹安全过滤器接收阶段的跨度

3.  `spring.security.http.chains.after` --- 包裹安全过滤器返回阶段的跨度

4.  `spring.security.http.secured.requests` ---
    包裹已被保护的应用请求的跨度

5.  `spring.security.http.unsecured.requests` --- 包裹未被 Spring
    Security 保护的请求的跨度

6.  `spring.security.authentications` --- 包裹认证尝试的跨度

7.  `spring.security.authorizations` --- 包裹授权尝试的跨度

:::: tip
::: title
:::

`spring.security.http.chains.before` +
`spring.security.http.secured.requests` +
`spring.security.http.chains.after` = `spring.security.http.requests`
`spring.security.http.chains.before` +
`spring.security.http.chains.after` = 请求中由 Spring Security
负责的部分
::::
