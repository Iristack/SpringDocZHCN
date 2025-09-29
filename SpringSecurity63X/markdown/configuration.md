以下步骤涉及如何配置 `HttpSecurity`、`WebSecurity` 及相关组件的变更。

# 使用 Lambda DSL {#_使用_lambda_dsl}

Lambda DSL 自 Spring Security 5.2 版本起引入，它允许使用 lambda
表达式来配置 HTTP 安全性。

你可能已经在 Spring Security
的文档或示例中见过这种配置风格。下面我们来看看使用 lambda 的 HTTP
安全配置与之前的配置方式有何不同。

:::: formalpara
::: title
使用 lambda 的配置
:::

``` java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/blog/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(formLogin -> formLogin
                .loginPage("/login")
                .permitAll()
            )
            .rememberMe(Customizer.withDefaults());

        return http.build();
    }
}
```
::::

:::: formalpara
::: title
不使用 lambda 的等效配置
:::

``` java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests()
                .requestMatchers("/blog/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .rememberMe();

        return http.build();
    }
}
```
::::

**Lambda DSL 是配置 Spring Security 的推荐方式**。在 Spring Security 7
中，旧的配置方式将不再有效，必须使用 Lambda DSL。这样做的主要原因有：

- 之前的方式如果不了解方法返回类型，就很难清楚哪个对象正在被配置。嵌套越深，越容易混淆。即使是经验丰富的用户，也可能误以为自己的配置实现了某种效果，但实际上却产生了不同的行为。

- **一致性**：许多代码库在两种风格之间切换，导致配置不一致，难以理解，常常引发错误配置。

## Lambda DSL 配置技巧 {#_lambda_dsl_配置技巧}

对比上面两个示例，你会注意到一些关键区别：

- 在 Lambda DSL 中，**无需再使用 `.and()` 方法链式连接配置项**。调用
  lambda 方法后，`HttpSecurity` 实例会自动返回，以便继续进行其他配置。

- `Customizer.withDefaults()` 用于以 Spring Security
  提供的默认值启用某项安全功能。这是对空 lambda 表达式 `it → {}`
  的一种简写形式。

## WebFlux 安全配置 {#_webflux_安全配置}

你也可以类似地使用 lambda 来配置 WebFlux 安全性。以下是一个使用 lambda
的 WebFlux 配置示例。

:::: formalpara
::: title
WebFlux 使用 lambda 的配置
:::

``` java
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/blog/**").permitAll()
                .anyExchange().authenticated()
            )
            .httpBasic(Customizer.withDefaults())
            .formLogin(formLogin -> formLogin
                .loginPage("/login")
            );

        return http.build();
    }

}
```
::::

## Lambda DSL 的设计目标 {#_lambda_dsl_的设计目标}

Lambda DSL 的设计旨在实现以下几个目标：

- **自动缩进使配置更易读**。

- **无需使用 `.and()` 进行链式调用**。

- Spring Security 的 DSL 风格与其他 Spring 项目中的 DSL（如 Spring
  Integration 和 Spring Cloud Gateway）保持一致，提升开发者体验。
