除了在请求级别建模授权之外，Spring Security 还支持在方法级别进行建模。

您可以通过将任何 `@Configuration` 类用 `@EnableMethodSecurity`
注解，或向任何 XML 配置文件中添加 `<method-security>`
来激活它，如下所示：

::: informalexample

Java

:   ``` java
    @EnableMethodSecurity
    ```

Kotlin

:   ``` kotlin
    @EnableMethodSecurity
    ```

Xml

:   ``` xml
    <sec:method-security/>
    ```
:::

然后，您可以立即使用
[`@PreAuthorize`](#use-preauthorize)、[`@PostAuthorize`](#use-postauthorize)、[`@PreFilter`](#use-prefilter)
和 [`@PostFilter`](#use-postfilter) 注解任何 Spring
管理的类或方法，以授权方法调用，包括输入参数和返回值。

:::: note
::: title
:::

{spring-boot-reference-url}using.html#using.build-systems.starters\[Spring
Boot Starter Security\] 默认不激活方法级授权。
::::

方法安全还支持许多其他用例，包括 [AspectJ
支持](#use-aspectj)、[自定义注解](#use-programmatic-authorization)
以及多个配置点。 考虑学习以下用例：

- [从 `@EnableGlobalMethodSecurity`
  迁移](#migration-enableglobalmethodsecurity)

- 理解 [方法安全的工作原理](#method-security-architecture) 及其使用原因

- 比较 [请求级和方法级授权](#request-vs-method)

- 使用 [`@PreAuthorize`](#use-preauthorize) 和
  [`@PostAuthorize`](#use-postauthorize) 授权方法

- 在授权被拒绝时提供 [回退值](#fallback-values-authorization-denied)

- 使用 [`@PreFilter`](#use-prefilter) 和
  [`@PostFilter`](#use-postfilter) 过滤方法

- 使用 [JSR-250 注解](#use-jsr250) 授权方法

- 使用 [AspectJ 表达式](#use-aspectj) 授权方法

- 集成 [AspectJ 字节码编织](#weave-aspectj)

- 与 [\@Transactional 和其他基于 AOP 的注解](#changing-the-order) 协调

- 自定义 [SpEL 表达式处理](#customizing-expression-handling)

- 集成 [自定义授权系统](#custom-authorization-managers)

# 方法安全如何工作 {#method-security-architecture}

Spring Security 的方法授权支持适用于：

- 提取细粒度的授权逻辑；例如，当方法参数和返回值影响授权决策时。

- 在服务层强制执行安全性

- 在风格上更倾向于基于注解而不是基于 `HttpSecurity` 的配置

由于方法安全是使用
{spring-framework-reference-url}core.html#aop-api\[Spring AOP\]
构建的，因此您可以访问其所有表达能力，以根据需要覆盖 Spring Security
的默认设置。

如前所述，您首先通过将 `@EnableMethodSecurity` 添加到 `@Configuration`
类或在 Spring XML 配置文件中添加 `<sec:method-security/>` 来开始。

:::: {#use-method-security .note}
::: title
:::

此注解和 XML 元素分别取代了 `@EnableGlobalMethodSecurity` 和
`<sec:global-method-security/>`。 它们提供了以下改进：

1.  使用简化的 `AuthorizationManager` API
    而不是元数据源、配置属性、决策管理器和投票者。 这简化了重用和定制。

2.  更倾向于直接基于 Bean 的配置，而不是要求扩展
    `GlobalMethodSecurityConfiguration` 来定制 Bean

3.  使用原生 Spring AOP 构建，减少了抽象，并允许您使用 Spring AOP
    构建块进行定制

4.  检查冲突的注解以确保安全配置明确无误

5.  符合 JSR-250

6.  默认启用 `@PreAuthorize`、`@PostAuthorize`、`@PreFilter` 和
    `@PostFilter`

如果您正在使用 `@EnableGlobalMethodSecurity` 或
`<global-method-security/>`，这些现在已弃用，建议您迁移。
::::

方法授权是方法前和方法后授权的组合。 考虑一个以以下方式注解的服务 Bean：

::: informalexample

Java

:   ``` java
    @Service
    public class MyCustomerService {
        @PreAuthorize("hasAuthority('permission:read')")
        @PostAuthorize("returnObject.owner == authentication.name")
        public Customer readCustomer(String id) { ... }
    }
    ```

Kotlin

:   ``` kotlin
    @Service
    open class MyCustomerService {
        @PreAuthorize("hasAuthority('permission:read')")
        @PostAuthorize("returnObject.owner == authentication.name")
        fun readCustomer(val id: String): Customer { ... }
    }
    ```
:::

当方法安全 [激活](#activate-method-security) 时，对
`MyCustomerService#readCustomer` 的给定调用可能如下所示：

![methodsecurity](servlet/authorization/methodsecurity.png)

1.  Spring AOP 调用其代理方法
    `readCustomer`。在代理的其他顾问中，它调用一个匹配 [`@PreAuthorize`
    切入点](#annotation-method-pointcuts) 的
    {security-api-url}org/springframework/security/authorization/method/AuthorizationManagerBeforeMethodInterceptor.html\[`AuthorizationManagerBeforeMethodInterceptor`\]

2.  拦截器调用
    {security-api-url}org/springframework/security/authorization/method/PreAuthorizeAuthorizationManager.html\[`PreAuthorizeAuthorizationManager#check`\]

3.  授权管理器使用 `MethodSecurityExpressionHandler` 解析注解的 [SpEL
    表达式](#authorization-expressions)，并从包含 [a
    `Supplier<Authentication>`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
    和 `MethodInvocation` 的 `MethodSecurityExpressionRoot` 构造相应的
    `EvaluationContext`

4.  拦截器使用此上下文评估表达式；具体来说，它从 `Supplier` 中读取 [the
    `Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
    并检查其是否在其
    [authorities](servlet/authorization/architecture.xml#authz-authorities)
    集合中有 `permission:read`

5.  如果评估通过，则 Spring AOP 继续调用该方法。

6.  如果没有通过，拦截器发布一个 `AuthorizationDeniedEvent` 并抛出一个
    {security-api-url}org/springframework/security/access/AccessDeniedException.html\[`AccessDeniedException`\]，[the
    `ExceptionTranslationFilter`](servlet/architecture.xml#servlet-exceptiontranslationfilter)
    会捕获该异常并向响应返回 403 状态码

7.  方法返回后，Spring AOP 调用一个匹配 [the `@PostAuthorize`
    pointcut](#annotation-method-pointcuts) 的
    {security-api-url}org/springframework/security/authorization/method/AuthorizationManagerAfterMethodInterceptor.html\[`AuthorizationManagerAfterMethodInterceptor`\]，操作与上述相同，但使用
    {security-api-url}org/springframework/security/authorization/method/PostAuthorizeAuthorizationManager.html\[`PostAuthorizeAuthorizationManager`\]

8.  如果评估通过（在这种情况下，返回值属于登录用户），则处理正常继续

9.  如果没有通过，拦截器发布一个 `AuthorizationDeniedEvent` 并抛出一个
    {security-api-url}org/springframework/security/access/AccessDeniedException.html\[`AccessDeniedException`\]，[the
    `ExceptionTranslationFilter`](servlet/architecture.xml#servlet-exceptiontranslationfilter)
    会捕获该异常并向响应返回 403 状态码

:::: note
::: title
:::

如果方法不是在 HTTP 请求的上下文中调用的，您可能需要自己处理
`AccessDeniedException`
::::

## 多个注解按顺序计算 {#unanimous-based-authorization-decisions}

如上所述，如果方法调用涉及多个
[方法安全注解](#authorizing-with-annotations)，每个注解都会依次处理。
这意味着它们可以被视为"与"在一起。
换句话说，要使调用获得授权，所有注解检查都需要通过授权。

## 不支持重复注解 {#repeated-annotations}

也就是说，不支持在同一方法上重复相同的注解。
例如，您不能在同一方法上放置两次 `@PreAuthorize`。

相反，请使用 SpEL 的布尔支持或其对委托给单独 Bean 的支持。

## 每个注解都有自己的切入点 {#annotation-method-pointcuts}

每个注解都有自己的切入点实例，该实例在整个对象层次结构中查找该注解或其
[元注解](#meta-annotations) 对应物，从
[方法及其封闭类](#class-or-interface-annotations) 开始。

您可以在
{security-api-url}org/springframework/security/authorization/method/AuthorizationMethodPointcuts.html\[`AuthorizationMethodPointcuts`\]
中查看此功能的具体细节。

## 每个注解都有自己的方法拦截器 {#annotation-method-interceptors}

每个注解都有其专用的方法拦截器。 这样做的原因是使其更具可组合性。
例如，如果需要，您可以禁用 Spring Security 的默认设置并 [仅发布
`@PostAuthorize` 方法拦截器](#_enabling_certain_annotations)。

方法拦截器如下：

- 对于 [`@PreAuthorize`](#use-preauthorize)，Spring Security 使用
  {security-api-url}org/springframework/security/authorization/method/AuthorizationManagerBeforeMethodInterceptor.html\[`AuthorizationManagerBeforeMethodInterceptor#preAuthorize`\]，进而使用
  {security-api-url}org/springframework/security/authorization/method/PreAuthorizeAuthorizationManager.html\[`PreAuthorizeAuthorizationManager`\]

- 对于 [`@PostAuthorize`](#use-postauthorize)，Spring Security 使用
  {security-api-url}org/springframework/security/authorization/method/AuthorizationManagerAfterMethodInterceptor.html\[`AuthorizationManagerBeforeMethodInterceptor#postAuthorize`\]，进而使用
  {security-api-url}org/springframework/security/authorization/method/PostAuthorizeAuthorizationManager.html\[`PostAuthorizeAuthorizationManager`\]

- 对于 [`@PreFilter`](#use-prefilter)，Spring Security 使用
  {security-api-url}org/springframework/security/authorization/method/PreFilterAuthorizationMethodInterceptor.html\[`PreFilterAuthorizationMethodInterceptor`\]

- 对于 [`@PostFilter`](#use-postfilter)，Spring Security 使用
  {security-api-url}org/springframework/security/authorization/method/PostFilterAuthorizationMethodInterceptor.html\[`PostFilterAuthorizationMethodInterceptor`\]

- 对于 [`@Secured`](#use-secured)，Spring Security 使用
  {security-api-url}org/springframework/security/authorization/method/AuthorizationManagerBeforeMethodInterceptor.html\[`AuthorizationManagerBeforeMethodInterceptor#secured`\]，进而使用
  {security-api-url}org/springframework/security/authorization/method/SecuredAuthorizationManager.html\[`SecuredAuthorizationManager`\]

- 对于 JSR-250 注解，Spring Security 使用
  {security-api-url}org/springframework/security/authorization/method/AuthorizationManagerBeforeMethodInterceptor.html\[`AuthorizationManagerBeforeMethodInterceptor#jsr250`\]，进而使用
  {security-api-url}org/springframework/security/authorization/method/Jsr250AuthorizationManager.html\[`Jsr250AuthorizationManager`\]

一般来说，您可以将以下列表视为在添加 `@EnableMethodSecurity` 时 Spring
Security 发布的拦截器的代表性示例：

::: informalexample

Java

:   ``` java
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor preAuthorizeMethodInterceptor() {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor postAuthorizeMethodInterceptor() {
        return AuthorizationManagerAfterMethodInterceptor.postAuthorize();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor preFilterMethodInterceptor() {
        return AuthorizationManagerBeforeMethodInterceptor.preFilter();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor postFilterMethodInterceptor() {
        return AuthorizationManagerAfterMethodInterceptor.postFilter();
    }
    ```
:::

## 倾向于授予权限而非复杂的 SpEL 表达式 {#favor-granting-authorities}

很多时候，引入像下面这样的复杂 SpEL 表达式可能会很诱人：

::: informalexample

Java

:   ``` java
    @PreAuthorize("hasAuthority('permission:read') || hasRole('ADMIN')")
    ```
:::

:::: formalpara
::: title
Kotlin
:::

``` kotlin
@PreAuthorize("hasAuthority('permission:read') || hasRole('ADMIN')")
```
::::

然而，您也可以将 `permission:read` 授予具有 `ROLE_ADMIN` 的人。
一种方法是使用 `RoleHierarchy`，如下所示：

::: informalexample

Java

:   ``` java
    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > permission:read");
    }
    ```

Kotlin

:   ``` kotlin
    companion object {
        @Bean
        fun roleHierarchy(): RoleHierarchy {
            return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > permission:read")
        }
    }
    ```

Xml

:   ``` xml
    <bean id="roleHierarchy"
            class="org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl" factory-method="fromHierarchy">
        <constructor-arg value="ROLE_ADMIN > permission:read"/>
    </bean>
    ```
:::

然后 [将其设置在 `MethodSecurityExpressionHandler`
实例中](#customizing-expression-handling)。 这允许您拥有更简单的
[`@PreAuthorize`](#use-preauthorize) 表达式，如下所示：

::: informalexample

Java

:   ``` java
    @PreAuthorize("hasAuthority('permission:read')")
    ```

Kotlin

:   ``` kotlin
    @PreAuthorize("hasAuthority('permission:read')")
    ```
:::

或者，在可能的情况下，将应用程序特定的授权逻辑适应为登录时授予的权限。

# 比较请求级与方法级授权 {#request-vs-method}

何时应该优先选择方法级授权而不是
[请求级授权](servlet/authorization/authorize-http-requests.xml)？
部分取决于个人喜好；但是，考虑以下每种情况的优点列表以帮助您决定。

+----------------------+----------------------+-----------------------+
|                      | **请求级**           | **方法级**            |
+----------------------+----------------------+-----------------------+
| **授权类型**         | 粗粒度               | 细粒度                |
+----------------------+----------------------+-----------------------+
| **配置位置**         | 在配置类中声明       | 在方法声明中局部      |
+----------------------+----------------------+-----------------------+
| **配置风格**         | DSL                  | 注解                  |
+----------------------+----------------------+-----------------------+
| **授权定义**         | 编程式               | SpEL                  |
+----------------------+----------------------+-----------------------+

主要权衡似乎在于您希望授权规则存在于何处。

:::: note
::: title
:::

重要的是要记住，当您使用基于注解的方法安全时，未注解的方法不会受到保护。
为了防止这种情况，请在您的
[`HttpSecurity`](servlet/configuration/java.xml#jc-httpsecurity)
实例中声明一个
[捕获所有授权规则](servlet/authorization/authorize-http-requests.xml#activate-request-security)。
::::

# 使用注解进行授权 {#authorizing-with-annotations}

Spring Security
启用方法级授权支持的主要方式是通过您可以添加到方法、类和接口的注解。

## 使用 `@PreAuthorize` 授权方法调用 {#use-preauthorize}

当 [方法安全处于活动状态](#activate-method-security)
时，您可以像这样使用
{security-api-url}org/springframework/security/access/prepost/PreAuthorize.html\[`@PreAuthorize`\]
注解来注解一个方法：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @PreAuthorize("hasRole('ADMIN')")
        public Account readAccount(Long id) {
            // ... 仅当 `Authentication` 拥有 `ROLE_ADMIN` 权限时才会调用
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    open class BankService {
        @PreAuthorize("hasRole('ADMIN')")
        fun readAccount(val id: Long): Account {
            // ... 仅当 `Authentication` 拥有 `ROLE_ADMIN` 权限时才会调用
        }
    }
    ```
:::

这表示只有当提供的表达式 `hasRole('ADMIN')` 通过时，该方法才能被调用。

然后，您可以 [测试该类](servlet/test/method.xml)
以确认它正在强制执行授权规则，如下所示：

::: informalexample

Java

:   ``` java
    @Autowired
    BankService bankService;

    @WithMockUser(roles="ADMIN")
    @Test
    void readAccountWithAdminRoleThenInvokes() {
        Account account = this.bankService.readAccount("12345678");
        // ... 断言
    }

    @WithMockUser(roles="WRONG")
    @Test
    void readAccountWithWrongRoleThenAccessDenied() {
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(
            () -> this.bankService.readAccount("12345678"));
    }
    ```

Kotlin

:   ``` kotlin
    @WithMockUser(roles="ADMIN")
    @Test
    fun readAccountWithAdminRoleThenInvokes() {
        val account: Account = this.bankService.readAccount("12345678")
        // ... 断言
    }

    @WithMockUser(roles="WRONG")
    @Test
    fun readAccountWithWrongRoleThenAccessDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            this.bankService.readAccount("12345678")
        }
    }
    ```
:::

:::: tip
::: title
:::

`@PreAuthorize` 也可以是 [元注解](#meta-annotations)，可以在
[类或接口级别](#class-or-interface-annotations) 定义，并使用 [SpEL
授权表达式](#authorization-expressions)。
::::

虽然 `@PreAuthorize`
对于声明所需权限非常有用，但它也可以用于评估涉及方法参数的更复杂的
[表达式](#using_method_parameters)。

## 使用 `@PostAuthorize` 授权方法结果 {#use-postauthorize}

当方法安全处于活动状态时，您可以像这样使用
{security-api-url}org/springframework/security/access/prepost/PostAuthorize.html\[`@PostAuthorize`\]
注解来注解一个方法：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @PostAuthorize("returnObject.owner == authentication.name")
        public Account readAccount(Long id) {
            // ... 仅当 `Account` 属于登录用户时才会返回
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    open class BankService {
        @PostAuthorize("returnObject.owner == authentication.name")
        fun readAccount(val id: Long): Account {
            // ... 仅当 `Account` 属于登录用户时才会返回
        }
    }
    ```
:::

这表示只有当提供的表达式 `returnObject.owner == authentication.name`
通过时，该方法才能返回值。 `returnObject` 表示要返回的 `Account` 对象。

然后，您可以 [测试该类](servlet/test/method.xml)
以确认它正在强制执行授权规则：

::: informalexample

Java

:   ``` java
    @Autowired
    BankService bankService;

    @WithMockUser(username="owner")
    @Test
    void readAccountWhenOwnedThenReturns() {
        Account account = this.bankService.readAccount("12345678");
        // ... 断言
    }

    @WithMockUser(username="wrong")
    @Test
    void readAccountWhenNotOwnedThenAccessDenied() {
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(
            () -> this.bankService.readAccount("12345678"));
    }
    ```

Kotlin

:   ``` kotlin
    @WithMockUser(username="owner")
    @Test
    fun readAccountWhenOwnedThenReturns() {
        val account: Account = this.bankService.readAccount("12345678")
        // ... 断言
    }

    @WithMockUser(username="wrong")
    @Test
    fun readAccountWhenNotOwnedThenAccessDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            this.bankService.readAccount("12345678")
        }
    }
    ```
:::

:::: tip
::: title
:::

`@PostAuthorize` 也可以是 [元注解](#meta-annotations)，可以在
[类或接口级别](#class-or-interface-annotations) 定义，并使用 [SpEL
授权表达式](#authorization-expressions)。
::::

`@PostAuthorize` 特别有助于防御
[不安全的直接对象引用](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)。
事实上，它可以被定义为一个 [元注解](#meta-annotations)，如下所示：

::: informalexample

Java

:   ``` java
    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @PostAuthorize("returnObject.owner == authentication.name")
    public @interface RequireOwnership {}
    ```

Kotlin

:   ``` kotlin
    @Target(ElementType.METHOD, ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @PostAuthorize("returnObject.owner == authentication.name")
    annotation class RequireOwnership
    ```
:::

允许您以以下方式注解服务：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @RequireOwnership
        public Account readAccount(Long id) {
            // ... 仅当 `Account` 属于登录用户时才会返回
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    open class BankService {
        @RequireOwnership
        fun readAccount(val id: Long): Account {
            // ... 仅当 `Account` 属于登录用户时才会返回
        }
    }
    ```
:::

结果是，上述方法只有在 `owner` 属性与登录用户的 `name` 匹配时才会返回
`Account`。 否则，Spring Security 将抛出一个 `AccessDeniedException`
并返回 403 状态码。

## 使用 `@PreFilter` 过滤方法参数 {#use-prefilter}

:::: note
::: title
:::

`@PreFilter` 尚不支持 Kotlin 特有的数据类型；因此，仅显示 Java 代码片段
::::

当方法安全处于活动状态时，您可以像这样使用
{security-api-url}org/springframework/security/access/prepost/PreFilter.html\[`@PreFilter`\]
注解来注解一个方法：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @PreFilter("filterObject.owner == authentication.name")
        public Collection<Account> updateAccounts(Account... accounts) {
            // ... `accounts` 将只包含由登录用户拥有的账户
            return updated;
        }
    }
    ```
:::

这意味着将过滤掉 `accounts` 中表达式
`filterObject.owner == authentication.name` 失败的任何值。
`filterObject` 表示 `accounts` 中的每个 `account`，并用于测试每个
`account`。

然后，您可以按以下方式测试该类以确认它正在强制执行授权规则：

::: informalexample

Java

:   ``` java
    @Autowired
    BankService bankService;

    @WithMockUser(username="owner")
    @Test
    void updateAccountsWhenOwnedThenReturns() {
        Account ownedBy = ...
        Account notOwnedBy = ...
        Collection<Account> updated = this.bankService.updateAccounts(ownedBy, notOwnedBy);
        assertThat(updated).containsOnly(ownedBy);
    }
    ```
:::

:::: tip
::: title
:::

`@PreFilter` 也可以是 [元注解](#meta-annotations)，可以在
[类或接口级别](#class-or-interface-annotations) 定义，并使用 [SpEL
授权表达式](#authorization-expressions)。
::::

`@PreFilter` 支持数组、集合、映射和流（只要流仍然打开）。

例如，上述 `updateAccounts` 声明将与以下其他四种方式功能相同：

::: informalexample

Java

:   ``` java
    @PreFilter("filterObject.owner == authentication.name")
    public Collection<Account> updateAccounts(Account[] accounts)

    @PreFilter("filterObject.owner == authentication.name")
    public Collection<Account> updateAccounts(Collection<Account> accounts)

    @PreFilter("filterObject.value.owner == authentication.name")
    public Collection<Account> updateAccounts(Map<String, Account> accounts)

    @PreFilter("filterObject.owner == authentication.name")
    public Collection<Account> updateAccounts(Stream<Account> accounts)
    ```
:::

结果是，上述方法将只包含其 `owner` 属性与登录用户 `name` 匹配的
`Account` 实例。

## 使用 `@PostFilter` 过滤方法结果 {#use-postfilter}

:::: note
::: title
:::

`@PostFilter` 尚不支持 Kotlin 特有的数据类型；因此，仅显示 Java 代码片段
::::

当方法安全处于活动状态时，您可以像这样使用
{security-api-url}org/springframework/security/access/prepost/PostFilter.html\[`@PostFilter`\]
注解来注解一个方法：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @PostFilter("filterObject.owner == authentication.name")
        public Collection<Account> readAccounts(String... ids) {
            // ... 返回值将被过滤，只包含由登录用户拥有的账户
            return accounts;
        }
    }
    ```
:::

这意味着将过滤掉返回值中表达式
`filterObject.owner == authentication.name` 失败的任何值。
`filterObject` 表示 `accounts` 中的每个 `account`，并用于测试每个
`account`。

然后，您可以像这样测试该类以确认它正在强制执行授权规则：

::: informalexample

Java

:   ``` java
    @Autowired
    BankService bankService;

    @WithMockUser(username="owner")
    @Test
    void readAccountsWhenOwnedThenReturns() {
        Collection<Account> accounts = this.bankService.updateAccounts("owner", "not-owner");
        assertThat(accounts).hasSize(1);
        assertThat(accounts.get(0).getOwner()).isEqualTo("owner");
    }
    ```
:::

:::: tip
::: title
:::

`@PostFilter` 也可以是 [元注解](#meta-annotations)，可以在
[类或接口级别](#class-or-interface-annotations) 定义，并使用 [SpEL
授权表达式](#authorization-expressions)。
::::

`@PostFilter` 支持数组、集合、映射和流（只要流仍然打开）。

例如，上述 `readAccounts` 声明将与以下其他三种方式功能相同：

``` java
@PostFilter("filterObject.owner == authentication.name")
public Account[] readAccounts(String... ids)

@PostFilter("filterObject.value.owner == authentication.name")
public Map<String, Account> readAccounts(String... ids)

@PostFilter("filterObject.owner == authentication.name")
public Stream<Account> readAccounts(String... ids)
```

结果是，上述方法将返回其 `owner` 属性与登录用户 `name` 匹配的 `Account`
实例。

:::: note
::: title
:::

内存中的过滤显然可能很昂贵，因此请考虑是否最好改为在数据层
[过滤数据](servlet/integrations/data.xml)。
::::

## 使用 `@Secured` 授权方法调用 {#use-secured}

{security-api-url}org/springframework/security/access/annotation/Secured.html\[`@Secured`\]
是用于授权调用的遗留选项。 [`@PreAuthorize`](#use-preauthorize)
取代了它，因此推荐使用。

要使用 `@Secured` 注解，您应首先更改方法安全声明以启用它，如下所示：

::: informalexample

Java

:   ``` java
    @EnableMethodSecurity(securedEnabled = true)
    ```

Kotlin

:   ``` kotlin
    @EnableMethodSecurity(securedEnabled = true)
    ```

Xml

:   ``` xml
    <sec:method-security secured-enabled="true"/>
    ```
:::

这将导致 Spring Security 发布
[相应的方法拦截器](#annotation-method-interceptors)，该拦截器对使用
`@Secured` 注解的方法、类和接口进行授权。

## 使用 JSR-250 注解授权方法调用 {#use-jsr250}

如果您想使用 [JSR-250](https://jcp.org/en/jsr/detail?id=250)
注解，Spring Security 也支持这一点。
[`@PreAuthorize`](#use-preauthorize) 具有更强的表达能力，因此推荐使用。

要使用 JSR-250 注解，您应首先更改方法安全声明以启用它们，如下所示：

::: informalexample

Java

:   ``` java
    @EnableMethodSecurity(jsr250Enabled = true)
    ```

Kotlin

:   ``` kotlin
    @EnableMethodSecurity(jsr250Enabled = true)
    ```

Xml

:   ``` xml
    <sec:method-security jsr250-enabled="true"/>
    ```
:::

这将导致 Spring Security 发布
[相应的方法拦截器](#annotation-method-interceptors)，该拦截器对使用
`@RolesAllowed`、`@PermitAll` 和 `@DenyAll`
注解的方法、类和接口进行授权。

## 在类或接口级别声明注解 {#class-or-interface-annotations}

也支持在类和接口级别使用方法安全注解。

如果在类级别如下所示：

::: informalexample

Java

:   ``` java
    @Controller
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public class MyController {
        @GetMapping("/endpoint")
        public String endpoint() { ... }
    }
    ```

Kotlin

:   ``` kotlin
    @Controller
    @PreAuthorize("hasAuthority('ROLE_USER')")
    open class MyController {
        @GetMapping("/endpoint")
        fun endpoint(): String { ... }
    }
    ```
:::

那么所有方法都继承类级别的行为。

或者，如果在类和方法级别都声明如下：

::: informalexample

Java

:   ``` java
    @Controller
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public class MyController {
        @GetMapping("/endpoint")
        @PreAuthorize("hasAuthority('ROLE_ADMIN')")
        public String endpoint() { ... }
    }
    ```

Kotlin

:   ``` kotlin
    @Controller
    @PreAuthorize("hasAuthority('ROLE_USER')")
    open class MyController {
        @GetMapping("/endpoint")
        @PreAuthorize("hasAuthority('ROLE_ADMIN')")
        fun endpoint(): String { ... }
    }
    ```
:::

那么声明注解的方法会覆盖类级别的注解。

接口也是如此，但有一个例外：如果一个类从两个不同的接口继承注解，则启动将失败。
这是因为 Spring Security 无法判断您想使用哪一个。

在这种情况下，您可以通过在具体方法上添加注解来解决歧义。

## 使用元注解 {#meta-annotations}

方法安全支持元注解。
这意味着您可以采用任何注解并根据您的特定应用用例提高可读性。

例如，您可以将 `@PreAuthorize("hasRole('ADMIN')")` 简化为
`@IsAdmin`，如下所示：

::: informalexample

Java

:   ``` java
    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('ADMIN')")
    public @interface IsAdmin {}
    ```

Kotlin

:   ``` kotlin
    @Target(ElementType.METHOD, ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('ADMIN')")
    annotation class IsAdmin
    ```
:::

结果是，在您的安全方法上，您现在可以这样做：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @IsAdmin
        public Account readAccount(Long id) {
            // ... 仅当 `Account` 属于登录用户时才返回
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    open class BankService {
        @IsAdmin
        fun readAccount(val id: Long): Account {
            // ... 仅当 `Account` 属于登录用户时才返回
        }
    }
    ```
:::

这使得方法定义更具可读性。

### 模板化元注解表达式 {#_模板化元注解表达式}

您还可以选择使用元注解模板，这允许更强大的注解定义。

首先，发布以下 Bean：

::: informalexample

Java

:   ``` java
    @Bean
    static PrePostTemplateDefaults prePostTemplateDefaults() {
        return new PrePostTemplateDefaults();
    }
    ```

Kotlin

:   ``` kotlin
    companion object {
        @Bean
        fun prePostTemplateDefaults(): PrePostTemplateDefaults {
            return PrePostTemplateDefaults()
        }
    }
    ```
:::

现在，您可以创建比 `@IsAdmin` 更强大的东西，比如 `@HasRole`，如下所示：

::: informalexample

Java

:   ``` java
    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('{value}')")
    public @interface HasRole {
        String value();
    }
    ```

Kotlin

:   ``` kotlin
    @Target(ElementType.METHOD, ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('{value}')")
    annotation class HasRole(val value: String)
    ```
:::

结果是，在您的安全方法上，您现在可以这样做：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @HasRole("ADMIN")
        public Account readAccount(Long id) {
            // ... 仅当 `Account` 属于登录用户时才返回
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    open class BankService {
        @HasRole("ADMIN")
        fun readAccount(val id: Long): Account {
            // ... 仅当 `Account` 属于登录用户时才返回
        }
    }
    ```
:::

请注意，这也适用于方法变量和所有注解类型，尽管您需要注意正确处理引号，以便生成的
SpEL 表达式是正确的。

例如，考虑以下 `@HasAnyRole` 注解：

::: informalexample

Java

:   ``` java
    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAnyRole({roles})")
    public @interface HasAnyRole {
        String[] roles();
    }
    ```

Kotlin

:   ``` kotlin
    @Target(ElementType.METHOD, ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAnyRole({roles})")
    annotation class HasAnyRole(val roles: Array<String>)
    ```
:::

在这种情况下，您会注意到不应在表达式中使用引号，而应在参数值中使用，如下所示：

::: informalexample

Java

:   ``` java
    @Component
    public class BankService {
        @HasAnyRole(roles = { "'USER'", "'ADMIN'" })
        public Account readAccount(Long id) {
            // ... 仅当 `Account` 属于登录用户时才返回
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    open class BankService {
        @HasAnyRole(roles = arrayOf("'USER'", "'ADMIN'"))
        fun readAccount(val id: Long): Account {
            // ... 仅当 `Account` 属于登录用户时才返回
        }
    }
    ```
:::

以便替换后，表达式变为 `@PreAuthorize("hasAnyRole('USER', 'ADMIN')")`。

## 启用特定注解 {#enable-annotation}

您可以关闭 `@EnableMethodSecurity` 的预配置并替换为您自己的配置。 如果要
[自定义 `AuthorizationManager`](#custom-authorization-managers) 或
`Pointcut`，可以选择这样做。 或者您可能只想启用特定的注解，比如
`@PostAuthorize`。

您可以通过以下方式实现：

:::: example
::: title
仅 \@PostAuthorize 配置
:::

Java

:   ``` java
    @Configuration
    @EnableMethodSecurity(prePostEnabled = false)
    class MethodSecurityConfig {
        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        Advisor postAuthorize() {
            return AuthorizationManagerAfterMethodInterceptor.postAuthorize();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableMethodSecurity(prePostEnabled = false)
    class MethodSecurityConfig {
        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        fun postAuthorize() : Advisor {
            return AuthorizationManagerAfterMethodInterceptor.postAuthorize()
        }
    }
    ```

Xml

:   ``` xml
    <sec:method-security pre-post-enabled="false"/>

    <aop:config/>

    <bean id="postAuthorize"
        class="org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor"
        factory-method="postAuthorize"/>
    ```
::::

上述代码片段通过首先禁用方法安全的预配置，然后发布 [`@PostAuthorize`
拦截器](#annotation-method-interceptors) 本身来实现这一点。

# 使用 `<intercept-methods>` 进行授权 {#use-intercept-methods}

虽然使用 Spring Security 的
[基于注解的支持](#authorizing-with-annotations)
是方法安全的首选方式，但您也可以使用 XML 声明 Bean 授权规则。

如果需要在 XML 配置中声明，可以使用
[`<intercept-methods>`](servlet/appendix/namespace/method-security.xml#nsa-intercept-methods)，如下所示：

::: informalexample

Xml

:   ``` xml
    <bean class="org.mycompany.MyController">
        <intercept-methods>
            <protect method="get*" access="hasAuthority('read')"/>
            <protect method="*" access="hasAuthority('write')"/>
        </intercept-methods>
    </bean>
    ```
:::

:::: note
::: title
:::

这仅支持按前缀或名称匹配方法。 如果您的需求比这更复杂，请改用
[使用注解支持](#authorizing-with-annotations)。
::::

# 编程方式授权方法 {#use-programmatic-authorization}

正如您已经看到的，有几种方法可以使用 [方法安全 SpEL
表达式](#authorization-expressions) 指定非平凡的授权规则。

还有几种方法可以让您的逻辑基于 Java 而不是基于 SpEL。
这使我们能够访问整个 Java 语言，以增强可测试性和流程控制。

## 在 SpEL 中使用自定义 Bean {#_在_spel_中使用自定义_bean}

编程方式授权方法的第一种方法是两步过程。

首先，声明一个 Bean，该 Bean 有一个接受
`MethodSecurityExpressionOperations` 实例的方法，如下所示：

::: informalexample

Java

:   ``` java
    @Component("authz")
    public class AuthorizationLogic {
        public boolean decide(MethodSecurityExpressionOperations operations) {
            // ... 授权逻辑
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component("authz")
    open class AuthorizationLogic {
        fun decide(val operations: MethodSecurityExpressionOperations): boolean {
            // ... 授权逻辑
        }
    }
    ```
:::

然后，以以下方式在注解中引用该 Bean：

::: informalexample

Java

:   ``` java
    @Controller
    public class MyController {
        @PreAuthorize("@authz.decide(#root)")
        @GetMapping("/endpoint")
        public String endpoint() {
            // ...
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Controller
    open class MyController {
        @PreAuthorize("@authz.decide(#root)")
        @GetMapping("/endpoint")
        fun String endpoint() {
            // ...
        }
    }
    ```
:::

对于每次方法调用，Spring Security 都会调用该 Bean 上的给定方法。

这样做的好处是，所有授权逻辑都在一个独立的类中，可以独立进行单元测试和验证其正确性。
它还可以访问完整的 Java 语言。

:::: tip
::: title
:::

除了返回 `Boolean` 外，您还可以返回 `null` 以表示代码放弃做出决定。
::::

如果您想包含更多关于决策性质的信息，可以返回自定义的
`AuthorizationDecision`，如下所示：

::: informalexample

Java

:   ``` java
    @Component("authz")
    public class AuthorizationLogic {
        public AuthorizationDecision decide(MethodSecurityExpressionOperations operations) {
            // ... 授权逻辑
            return new MyAuthorizationDecision(false, details);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component("authz")
    open class AuthorizationLogic {
        fun decide(val operations: MethodSecurityExpressionOperations): AuthorizationDecision {
            // ... 授权逻辑
            return MyAuthorizationDecision(false, details)
        }
    }
    ```
:::

或者抛出一个自定义的 `AuthorizationDeniedException` 实例。
不过请注意，返回对象是首选，因为这样不会产生生成堆栈跟踪的开销。

然后，当您
[自定义如何处理授权结果](#fallback-values-authorization-denied)
时，可以访问自定义详细信息。

## 使用自定义授权管理器 {#custom-authorization-managers}

编程方式授权方法的第二种方法是创建一个自定义的
[`AuthorizationManager`](servlet/authorization/architecture.xml#_the_authorizationmanager)。

首先，声明一个授权管理器实例，也许像这样：

::: informalexample

Java

:   ``` java
    @Component
    public class MyAuthorizationManager implements AuthorizationManager<MethodInvocation>, AuthorizationManager<MethodInvocationResult> {
        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation invocation) {
            // ... 授权逻辑
        }

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocationResult invocation) {
            // ... 授权逻辑
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    class MyAuthorizationManager : AuthorizationManager<MethodInvocation>, AuthorizationManager<MethodInvocationResult> {
        override fun check(authentication: Supplier<Authentication>, invocation: MethodInvocation): AuthorizationDecision {
            // ... 授权逻辑
        }

        override fun check(authentication: Supplier<Authentication>, invocation: MethodInvocationResult): AuthorizationDecision {
            // ... 授权逻辑
        }
    }
    ```
:::

然后，发布带有切点的方法拦截器，该切点对应于您希望
`AuthorizationManager` 运行的时间。 例如，您可以像这样替换
`@PreAuthorize` 和 `@PostAuthorize` 的工作方式：

:::: example
::: title
仅 \@PreAuthorize 和 \@PostAuthorize 配置
:::

Java

:   ``` java
    @Configuration
    @EnableMethodSecurity(prePostEnabled = false)
    class MethodSecurityConfig {
        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        Advisor preAuthorize(MyAuthorizationManager manager) {
            return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(manager);
        }

        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        Advisor postAuthorize(MyAuthorizationManager manager) {
            return AuthorizationManagerAfterMethodInterceptor.postAuthorize(manager);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Configuration
    @EnableMethodSecurity(prePostEnabled = false)
    class MethodSecurityConfig {
        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        fun preAuthorize(val manager: MyAuthorizationManager) : Advisor {
            return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(manager)
        }

        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        fun postAuthorize(val manager: MyAuthorizationManager) : Advisor {
            return AuthorizationManagerAfterMethodInterceptor.postAuthorize(manager)
        }
    }
    ```

Xml

:   ``` xml
    <sec:method-security pre-post-enabled="false"/>

    <aop:config/>

    <bean id="preAuthorize"
        class="org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor"
        factory-method="preAuthorize">
        <constructor-arg ref="myAuthorizationManager"/>
    </bean>

    <bean id="postAuthorize"
        class="org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor"
        factory-method="postAuthorize">
        <constructor-arg ref="myAuthorizationManager"/>
    </bean>
    ```
::::

:::: tip
::: title
:::

您可以使用 `AuthorizationInterceptorsOrder` 中指定的顺序常量将拦截器放在
Spring Security 方法拦截器之间。
::::

## 自定义表达式处理 {#customizing-expression-handling}

第三，您可以自定义每个 SpEL 表达式的处理方式。
为此，您可以暴露一个自定义的
{security-api-url}org.springframework.security.access.expression.method.MethodSecurityExpressionHandler.html\[`MethodSecurityExpressionHandler`\]，如下所示：

:::: example
::: title
自定义 MethodSecurityExpressionHandler
:::

Java

:   ``` java
    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }
    ```

Kotlin

:   ``` kotlin
    companion object {
        @Bean
        fun methodSecurityExpressionHandler(val roleHierarchy: RoleHierarchy) : MethodSecurityExpressionHandler {
            val handler = DefaultMethodSecurityExpressionHandler()
            handler.setRoleHierarchy(roleHierarchy)
            return handler
        }
    }
    ```

Xml

:   ``` xml
    <sec:method-security>
        <sec:expression-handler ref="myExpressionHandler"/>
    </sec:method-security>

    <bean id="myExpressionHandler"
            class="org.springframework.security.messaging.access.expression.DefaultMessageSecurityExpressionHandler">
        <property name="roleHierarchy" ref="roleHierarchy"/>
    </bean>
    ```
::::

:::: tip
::: title
:::

我们使用 `static` 方法暴露 `MethodSecurityExpressionHandler`，以确保
Spring 在初始化 Spring Security 的方法安全 `@Configuration` 类之前发布它
::::

您还可以 [子类化
`DefaultMessageSecurityExpressionHandler`](#subclass-defaultmethodsecurityexpressionhandler)
以添加超出默认值的自定义授权表达式。

# 使用 AspectJ 进行授权 {#use-aspectj}

## 使用自定义切点匹配方法 {#match-by-pointcut}

基于 Spring AOP 构建，您可以声明与注解无关的模式，类似于
[请求级授权](servlet/authorization/authorize-http-requests.xml)。
这有可能集中方法级授权规则。

例如，您可以发布自己的 `Advisor` 或使用
[`<protect-pointcut>`](servlet/appendix/namespace/method-security.xml#nsa-protect-pointcut)
将 AOP 表达式与服务层的授权规则匹配，如下所示：

::: informalexample

Java

:   ``` java
    import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor protectServicePointcut() {
        AspectJExpressionPointcut pattern = new AspectJExpressionPointcut()
        pattern.setExpression("execution(* com.mycompany.*Service.*(..))")
        return new AuthorizationManagerBeforeMethodInterceptor(pattern, hasRole("USER"))
    }
    ```

Kotlin

:   ``` kotlin
    import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole

    companion object {
        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        fun protectServicePointcut(): Advisor {
            val pattern = AspectJExpressionPointcut()
            pattern.setExpression("execution(* com.mycompany.*Service.*(..))")
            return new AuthorizationManagerBeforeMethodInterceptor(pattern, hasRole("USER"))
        }
    }
    ```

Xml

:   ``` xml
    <sec:method-security>
        <protect-pointcut expression="execution(* com.mycompany.*Service.*(..))" access="hasRole('USER')"/>
    </sec:method-security>
    ```
:::

## 集成 AspectJ 字节码编织 {#weave-aspectj}

有时，通过使用 AspectJ 将 Spring Security 建议编织到 Bean
的字节码中，可以提高性能。

设置好 AspectJ 后，您可以在 `@EnableMethodSecurity` 注解或
`<method-security>` 元素中简单地声明您正在使用 AspectJ：

::: informalexample

Java

:   ``` java
    @EnableMethodSecurity(mode=AdviceMode.ASPECTJ)
    ```

Kotlin

:   ``` kotlin
    @EnableMethodSecurity(mode=AdviceMode.ASPECTJ)
    ```

Xml

:   ``` xml
    <sec:method-security mode="aspectj"/>
    ```
:::

结果将是 Spring Security 将其顾问发布为 AspectJ
建议，以便相应地进行编织。

# 指定顺序 {#changing-the-order}

如前所述，每个注解都有一个 Spring AOP 方法拦截器，每个拦截器在 Spring
AOP 顾问链中都有一个位置。

即，`@PreFilter` 方法拦截器的顺序是 100，`@PreAuthorize` 的顺序是
200，依此类推。

注意这一点很重要，因为还有其他基于 AOP 的注解，如
`@EnableTransactionManagement`，其顺序为 `Integer.MAX_VALUE`。
换句话说，默认情况下它们位于顾问链的末尾。

有时，让其他建议在 Spring Security 之前执行是有价值的。
例如，如果有一个方法同时使用 `@Transactional` 和 `@PostAuthorize`
注解，您可能希望事务在 `@PostAuthorize` 运行时仍然打开，以便
`AccessDeniedException` 会导致回滚。

为了让 `@EnableTransactionManagement`
在方法授权建议运行之前打开事务，您可以像这样设置
`@EnableTransactionManagement` 的顺序：

::: informalexample

Java

:   ``` java
    @EnableTransactionManagement(order = 0)
    ```

Kotlin

:   ``` kotlin
    @EnableTransactionManagement(order = 0)
    ```

Xml

:   ``` xml
    <tx:annotation-driven ref="txManager" order="0"/>
    ```
:::

由于最早的拦截器（`@PreFilter`）的顺序设置为
100，因此零的设置意味着事务建议将在所有 Spring Security 建议之前运行。

# 使用 SpEL 表达授权 {#authorization-expressions}

您已经看到了几个使用 SpEL 的例子，现在让我们更深入地了解 API。

Spring Security 将其所有授权字段和方法封装在一组根对象中。
最通用的根对象称为 `SecurityExpressionRoot`，它是
`MethodSecurityExpressionRoot` 的基础。 Spring Security
在准备评估授权表达式时，会将此根对象提供给
`MethodSecurityEvaluationContext`。

## 使用授权表达式字段和方法 {#using-authorization-expression-fields-and-methods}

这首先为您的 SpEL 表达式提供了一组增强的授权字段和方法。
以下是常见方法的快速概述：

- `permitAll` - 该方法调用不需要任何授权；请注意，在这种情况下，[the
  `Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
  从未从会话中检索

- `denyAll` -
  在任何情况下都不允许该方法；请注意，在这种情况下，`Authentication`
  从未从会话中检索

- `hasAuthority` - 该方法要求 `Authentication` 拥有与给定值匹配的 [a
  `GrantedAuthority`](servlet/authorization/architecture.xml#authz-authorities)

- `hasRole` - `hasAuthority` 的快捷方式，前缀为 `ROLE_`
  或配置的任何默认前缀

- `hasAnyAuthority` - 该方法要求 `Authentication` 拥有与任何给定值匹配的
  `GrantedAuthority`

- `hasAnyRole` - `hasAnyAuthority` 的快捷方式，前缀为 `ROLE_`
  或配置的任何默认前缀

- `hasPermission` - 连接到您的 `PermissionEvaluator`
  实例，用于对象级授权

以下是常见字段的简要介绍：

- `authentication` - 与此方法调用关联的 `Authentication` 实例

- `principal` - 与此方法调用关联的 `Authentication#getPrincipal`

现在了解了模式、规则以及它们如何配对，您应该能够理解这个更复杂示例中发生的情况：

:::: example
::: title
授权请求
:::

Java

:   ``` java
    @Component
    public class MyService {
        @PreAuthorize("denyAll") 
        MyResource myDeprecatedMethod(...);

        @PreAuthorize("hasRole('ADMIN')") 
        MyResource writeResource(...)

        @PreAuthorize("hasAuthority('db') and hasRole('ADMIN')") 
        MyResource deleteResource(...)

        @PreAuthorize("principal.claims['aud'] == 'my-audience'") 
        MyResource readResource(...);

        @PreAuthorize("@authz.check(authentication, #root)")
        MyResource shareResource(...);
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    open class MyService {
        @PreAuthorize("denyAll") 
        fun myDeprecatedMethod(...): MyResource

        @PreAuthorize("hasRole('ADMIN')") 
        fun writeResource(...): MyResource

        @PreAuthorize("hasAuthority('db') and hasRole('ADMIN')") 
        fun deleteResource(...): MyResource

        @PreAuthorize("principal.claims['aud'] == 'my-audience'") 
        fun readResource(...): MyResource

        @PreAuthorize("@authz.check(#root)")
        fun shareResource(...): MyResource
    }
    ```

Xml

:   ``` xml
    <sec:method-security>
        <protect-pointcut expression="execution(* com.mycompany.*Service.myDeprecatedMethod(..))" access="denyAll"/> 
        <protect-pointcut expression="execution(* com.mycompany.*Service.writeResource(..))" access="hasRole('ADMIN')"/> 
        <protect-pointcut expression="execution(* com.mycompany.*Service.deleteResource(..))" access="hasAuthority('db') and hasRole('ADMIN')"/> 
        <protect-pointcut expression="execution(* com.mycompany.*Service.readResource(..))" access="principal.claims['aud'] == 'my-audience'"/> 
        <protect-pointcut expression="execution(* com.mycompany.*Service.shareResource(..))" access="@authz.check(#root)"/> 
    </sec:method-security>
    ```
::::

- 此方法任何人都不得出于任何原因调用

- 此方法只能由授予 `ROLE_ADMIN` 权限的 `Authentication` 调用

- 此方法只能由授予 `db` 和 `ROLE_ADMIN` 权限的 `Authentication` 调用

- 此方法只能由 `aud` 声明等于 \"my-audience\" 的 `Princpal` 调用

- 此方法只能在 bean `authz` 的 `check` 方法返回 `true` 时调用

:::: tip
::: title
:::

您可以使用像上面 `authz` 这样的 Bean 来
[添加编程式授权](#_using_a_custom_bean_in_spel)。
::::

## 使用方法参数 {#using_method_parameters}

此外，Spring Security 提供了一种机制来发现方法参数，以便它们也可以在
SpEL 表达式中访问。

有关完整参考，Spring Security 使用
`DefaultSecurityParameterNameDiscoverer` 来发现参数名称。
默认情况下，对于一个方法，会尝试以下选项。

1.  如果 Spring Security 的 `@P`
    注解存在于方法的单个参数上，则使用该值。 以下示例使用 `@P` 注解：

    ::: informalexample

    Java

    :   ``` java
        import org.springframework.security.access.method.P;

        ...

        @PreAuthorize("hasPermission(#c, 'write')")
        public void updateContact(@P("c") Contact contact);
        ```

    Kotlin

    :   ``` kotlin
        import org.springframework.security.access.method.P

        ...

        @PreAuthorize("hasPermission(#c, 'write')")
        fun doSomething(@P("c") contact: Contact?)
        ```
    :::

    此表达式的意图是要求当前 `Authentication` 对此 `Contact` 实例具有
    `write` 权限。

    在后台，这是通过使用 `AnnotationParameterNameDiscoverer`
    实现的，您可以自定义以支持任何指定注解的值属性。

    - 如果 [Spring Data 的](servlet/integrations/data.xml) `@Param`
      注解至少存在于方法的一个参数上，则使用该值。 以下示例使用 `@Param`
      注解：

      ::: informalexample

      Java

      :   ``` java
          import org.springframework.data.repository.query.Param;

          ...

          @PreAuthorize("#n == authentication.name")
          Contact findContactByName(@Param("n") String name);
          ```

      Kotlin

      :   ``` kotlin
          import org.springframework.data.repository.query.Param

          ...

          @PreAuthorize("#n == authentication.name")
          fun findContactByName(@Param("n") name: String?): Contact?
          ```
      :::

      此表达式的意图是要求 `name` 等于 `Authentication#getName`
      才能授权调用。

      在后台，这是通过使用 `AnnotationParameterNameDiscoverer`
      实现的，您可以自定义以支持任何指定注解的值属性。

    - 如果您使用 `-parameters` 参数编译代码，则使用标准 JDK 反射 API
      发现参数名称。 这在类和接口上都有效。

    - 最后，如果您使用调试符号编译代码，则通过调试符号发现参数名称。
      这不适用于接口，因为它们没有关于参数名称的调试信息。
      对于接口，必须使用注解或 `-parameters` 方法。

# 授权任意对象 {#authorize-object}

Spring Security 还支持包装任何使用其方法安全注解注解的对象。

最简单的方法是在您希望授权的对象返回的方法上标记
`@AuthorizeReturnObject` 注解。

例如，考虑以下 `User` 类：

::: informalexample

Java

:   ``` java
    public class User {
        private String name;
        private String email;

        public User(String name, String email) {
            this.name = name;
            this.email = email;
        }

        public String getName() {
            return this.name;
        }

        @PreAuthorize("hasAuthority('user:read')")
        public String getEmail() {
            return this.email;
        }
    }
    ```

Kotlin

:   ``` kotlin
    class User (val name:String, @get:PreAuthorize("hasAuthority('user:read')") val email:String)
    ```
:::

给定这样一个接口：

::: informalexample

Java

:   ``` java
    public class UserRepository {
        @AuthorizeReturnObject
        Optional<User> findByName(String name) {
            // ...
        }
    }
    ```

Kotlin

:   ``` kotlin
    class UserRepository {
        @AuthorizeReturnObject
        fun findByName(name:String?): Optional<User?>? {
            // ...
        }
    }
    ```
:::

然后，从 `findById` 返回的任何 `User` 都将像其他 Spring Security
保护的组件一样受到保护：

::: informalexample

Java

:   ``` java
    @Autowired
    UserRepository users;

    @Test
    void getEmailWhenProxiedThenAuthorizes() {
        Optional<User> securedUser = users.findByName("name");
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> securedUser.get().getEmail());
    }
    ```

Kotlin

:   ``` kotlin
    import jdk.incubator.vector.VectorOperators.Test
    import java.nio.file.AccessDeniedException
    import java.util.*

    @Autowired
    var users:UserRepository? = null

    @Test
    fun getEmailWhenProxiedThenAuthorizes() {
        val securedUser: Optional<User> = users.findByName("name")
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy{securedUser.get().getEmail()}
    }
    ```
:::

## 在类级别使用 `@AuthorizeReturnObject` {#_在类级别使用_authorizereturnobject}

`@AuthorizeReturnObject` 可以放在类级别。但请注意，这意味着 Spring
Security 将尝试代理任何返回对象，包括 `String`、`Integer` 和其他类型。
这通常不是您想要的。

如果您想在方法返回值类型的类或接口上使用 `@AuthorizeReturnObject`，比如
`int`、`String`、`Double` 或这些类型的集合，那么您还应该发布适当的
`AuthorizationAdvisorProxyFactory.TargetVisitor`，如下所示：

::: informalexample

Java

:   ``` java
    @Bean
    static Customizer<AuthorizationAdvisorProxyFactory> skipValueTypes() {
        return (factory) -> factory.setTargetVisitor(TargetVisitor.defaultsSkipValueTypes());
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    open fun skipValueTypes() = Customizer<AuthorizationAdvisorProxyFactory> {
        it.setTargetVisitor(TargetVisitor.defaultsSkipValueTypes())
    }
    ```
:::

:::: tip
::: title
:::

您可以设置自己的 `AuthorizationAdvisorProxyFactory.TargetVisitor`
来自定义任何类型集的代理
::::

## 编程方式代理 {#_编程方式代理}

您还可以编程方式代理给定对象。

为此，您可以自动装配提供的 `AuthorizationProxyFactory`
实例，该实例基于您配置的方法安全拦截器。 如果您使用
`@EnableMethodSecurity`，则默认情况下它将具有
`@PreAuthorize`、`@PostAuthorize`、`@PreFilter` 和 `@PostFilter`
的拦截器。

您可以通过以下方式代理用户实例：

::: informalexample

Java

:   ``` java
    @Autowired
    AuthorizationProxyFactory proxyFactory;

    @Test
    void getEmailWhenProxiedThenAuthorizes() {
        User user = new User("name", "email");
        assertThat(user.getEmail()).isNotNull();
        User securedUser = proxyFactory.proxy(user);
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(securedUser::getEmail);
    }
    ```

Kotlin

:   ``` kotlin
    @Autowired
    var proxyFactory:AuthorizationProxyFactory? = null

    @Test
    fun getEmailWhenProxiedThenAuthorizes() {
        val user: User = User("name", "email")
        assertThat(user.getEmail()).isNotNull()
        val securedUser: User = proxyFactory.proxy(user)
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy(securedUser::getEmail)
    }
    ```
:::

## 手动构造 {#_手动构造}

如果您需要与 Spring Security 默认值不同的东西，也可以定义自己的实例。

例如，如果您像这样定义一个 `AuthorizationProxyFactory` 实例：

::: informalexample

Java

:   ``` java
    import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory.TargetVisitor;
    import static org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor.preAuthorize;
    // ...

    AuthorizationProxyFactory proxyFactory = AuthorizationAdvisorProxyFactory.withDefaults();
    // and if needing to skip value types
    proxyFactory.setTargetVisitor(TargetVisitor.defaultsSkipValueTypes());
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory.TargetVisitor;
    import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor.preAuthorize

    // ...

    val proxyFactory: AuthorizationProxyFactory = AuthorizationProxyFactory(preAuthorize())
    // and if needing to skip value types
    proxyFactory.setTargetVisitor(TargetVisitor.defaultsSkipValueTypes())
    ```
:::

然后您可以按如下方式包装任何 `User` 实例：

::: informalexample

Java

:   ``` java
    @Test
    void getEmailWhenProxiedThenAuthorizes() {
        AuthorizationProxyFactory proxyFactory = AuthorizationAdvisorProxyFactory.withDefaults();
        User user = new User("name", "email");
        assertThat(user.getEmail()).isNotNull();
        User securedUser = proxyFactory.proxy(user);
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(securedUser::getEmail);
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    fun getEmailWhenProxiedThenAuthorizes() {
        val proxyFactory: AuthorizationProxyFactory = AuthorizationAdvisorProxyFactory.withDefaults()
        val user: User = User("name", "email")
        assertThat(user.getEmail()).isNotNull()
        val securedUser: User = proxyFactory.proxy(user)
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy(securedUser::getEmail)
    }
    ```
:::

:::: note
::: title
:::

此功能尚不支持 Spring AOT
::::

## 代理集合 {#_代理集合}

`AuthorizationProxyFactory` 通过代理元素类型支持 Java
集合、流、数组、可选类型和迭代器，并通过代理值类型支持映射。

这意味着当代理 `List` 对象时，以下内容也适用：

::: informalexample

Java

:   ``` java
    @Test
    void getEmailWhenProxiedThenAuthorizes() {
        AuthorizationProxyFactory proxyFactory = AuthorizationAdvisorProxyFactory.withDefaults();
        List<User> users = List.of(ada, albert, marie);
        List<User> securedUsers = proxyFactory.proxy(users);
        securedUsers.forEach((securedUser) ->
            assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(securedUser::getEmail));
    }
    ```
:::

## 代理类 {#_代理类}

在有限的情况下，代理 `Class`
本身可能是有价值的，`AuthorizationProxyFactory` 也支持这一点。
这大致相当于在 Spring Framework 的代理创建支持中调用
`ProxyFactory#getProxyClass`。

一个方便的地方是当您需要提前构建代理类时，比如使用 Spring AOT。

## 支持所有方法安全注解 {#_支持所有方法安全注解}

`AuthorizationProxyFactory` 支持在您的应用程序中启用的任何方法安全注解。
它基于作为 Bean 发布的任何 `AuthorizationAdvisor` 类。

由于 `@EnableMethodSecurity` 默认发布
`@PreAuthorize`、`@PostAuthorize`、`@PreFilter` 和 `@PostFilter`
顾问，您通常不需要做任何事情来激活此功能。

:::: note
::: title
:::

使用 `returnObject` 或 `filterObject` 的 SpEL
表达式位于代理后面，因此可以完全访问对象。
::::

## 自定义建议 {#custom_advice}

如果您有其他安全建议也希望应用，可以像这样发布自己的
`AuthorizationAdvisor`：

::: informalexample

Java

:   ``` java
    @EnableMethodSecurity
    class SecurityConfig {
        @Bean
        static AuthorizationAdvisor myAuthorizationAdvisor() {
            return new AuthorizationAdvisor();
        }
    }
    ```

Kotlin

:   ``` kotlin
    @EnableMethodSecurity
    internal class SecurityConfig {
        @Bean
        fun myAuthorizationAdvisor(): AuthorizationAdvisor {
            return AuthorizationAdvisor()
        }
    ]
    ```
:::

Spring Security 将把该顾问添加到 `AuthorizationProxyFactory`
在代理对象时添加的一组建议中。

## 与 Jackson 一起工作 {#_与_jackson_一起工作}

此功能的一个强大用途是从控制器返回一个安全值，如下所示：

::: informalexample

Java

:   ``` java
    @RestController
    public class UserController {
        @Autowired
        AuthorizationProxyFactory proxyFactory;

        @GetMapping
        User currentUser(@AuthenticationPrincipal User user) {
            return this.proxyFactory.proxy(user);
        }
    }
    ```

Kotlin

:   ``` kotlin
    @RestController
    class UserController  {
        @Autowired
        var proxyFactory: AuthorizationProxyFactory? = null

        @GetMapping
        fun currentUser(@AuthenticationPrincipal user:User?): User {
            return proxyFactory.proxy(user)
        }
    }
    ```
:::

但是，如果您使用 Jackson，这可能会导致序列化错误，如下所示：

::: informalexample
com.fasterxml.jackson.databind.exc.InvalidDefinitionException: Direct
self-reference leading to cycle
:::

这是由于 Jackson 如何处理 CGLIB 代理。
为了解决这个问题，请将以下注解添加到 `User` 类的顶部：

::: informalexample

Java

:   ``` java
    @JsonSerialize(as = User.class)
    public class User {

    }
    ```

Kotlin

:   ``` kotlin
    @JsonSerialize(`as` = User::class)
    class User
    ```
:::

最后，您需要发布一个 [自定义拦截器](#custom_advice) 来捕获每个字段抛出的
`AccessDeniedException`，您可以这样做：

::: informalexample

Java

:   ``` java
    @Component
    public class AccessDeniedExceptionInterceptor implements AuthorizationAdvisor {
        private final AuthorizationAdvisor advisor = AuthorizationManagerBeforeMethodInterceptor.preAuthorize();

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            try {
                return invocation.proceed();
            } catch (AccessDeniedException ex) {
                return null;
            }
        }

        @Override
        public Pointcut getPointcut() {
            return this.advisor.getPointcut();
        }

        @Override
        public Advice getAdvice() {
            return this;
        }

        @Override
        public int getOrder() {
            return this.advisor.getOrder() - 1;
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    class AccessDeniedExceptionInterceptor: AuthorizationAdvisor {
        var advisor: AuthorizationAdvisor = AuthorizationManagerBeforeMethodInterceptor.preAuthorize()

        @Throws(Throwable::class)
        fun invoke(invocation: MethodInvocation): Any? {
            return try  {
                invocation.proceed()
            } catch (ex:AccessDeniedException) {
                null
            }
        }

         val pointcut: Pointcut
         get() = advisor.getPointcut()

         val advice: Advice
         get() = this

         val order: Int
         get() = advisor.getOrder() - 1
    }
    ```
:::

然后，您将根据用户的授权级别看到不同的 JSON 序列化。 如果他们没有
`user:read` 权限，他们将看到：

``` json
{
    "name" : "name",
    "email" : null
}
```

如果他们有该权限，他们将看到：

``` json
{
    "name" : "name",
    "email" : "email"
}
```

:::: tip
::: title
:::

您还可以添加 Spring Boot 属性
`spring.jackson.default-property-inclusion=non_null`
以排除空值，如果您也不希望向未经授权的用户透露 JSON 键。
::::

# 授权被拒绝时提供回退值 {#fallback-values-authorization-denied}

在某些场景中，您可能不希望在方法被调用且没有所需权限时抛出
`AuthorizationDeniedException`。
相反，您可能希望返回一个后处理的结果，比如一个掩码结果，或者在调用方法之前发生授权拒绝时返回一个默认值。

Spring Security 通过使用
{security-api-url}org/springframework/security/authorization/method/HandleAuthorizationDenied.html\[`@HandleAuthorizationDenied`\]
支持在方法调用时处理授权拒绝。 该处理器适用于发生在 [`@PreAuthorize` 和
`@PostAuthorize` 注解](#authorizing-with-annotations)
中的授权拒绝，以及方法调用本身抛出的
{security-api-url}org/springframework/security/authorization/AuthorizationDeniedException.html\[`AuthorizationDeniedException`\]。

让我们考虑 [前一节](#authorize-object) 的示例，但不再创建
`AccessDeniedExceptionInterceptor` 将 `AccessDeniedException` 转换为
`null` 返回值，而是使用 `@HandleAuthorizationDenied` 的 `handlerClass`
属性：

::: informalexample

Java

:   ``` java
    public class NullMethodAuthorizationDeniedHandler implements MethodAuthorizationDeniedHandler { 

        @Override
        public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
            return null;
        }

    }

    @Configuration
    @EnableMethodSecurity
    public class SecurityConfig {

        @Bean 
        public NullMethodAuthorizationDeniedHandler nullMethodAuthorizationDeniedHandler() {
            return new NullMethodAuthorizationDeniedHandler();
        }

    }

    public class User {
        // ...

        @PreAuthorize(value = "hasAuthority('user:read')")
        @HandleAuthorizationDenied(handlerClass = NullMethodAuthorizationDeniedHandler.class)
        public String getEmail() {
            return this.email;
        }
    }
    ```

Kotlin

:   ``` kotlin
    class NullMethodAuthorizationDeniedHandler : MethodAuthorizationDeniedHandler { 

        override fun handleDeniedInvocation(methodInvocation: MethodInvocation, authorizationResult: AuthorizationResult): Any {
            return null
        }

    }

    @Configuration
    @EnableMethodSecurity
    class SecurityConfig {

        @Bean 
        fun nullMethodAuthorizationDeniedHandler(): NullMethodAuthorizationDeniedHandler {
            return MaskMethodAuthorizationDeniedHandler()
        }

    }

    class User (val name:String, @PreAuthorize(value = "hasAuthority('user:read')") @HandleAuthorizationDenied(handlerClass = NullMethodAuthorizationDeniedHandler::class) val email:String) 
    ```
:::

- 创建一个返回 `null` 值的 `MethodAuthorizationDeniedHandler` 实现

- 将 `NullMethodAuthorizationDeniedHandler` 注册为 Bean

- 使用 `@HandleAuthorizationDenied` 注解方法并将
  `NullMethodAuthorizationDeniedHandler` 传递给 `handlerClass` 属性

然后，您可以验证返回的是 `null` 值而不是 `AccessDeniedException`：

:::: tip
::: title
:::

您也可以使用 `@Component` 注解您的类，而不是创建 `@Bean` 方法
::::

::: informalexample

Java

:   ``` java
    @Autowired
    UserRepository users;

    @Test
    void getEmailWhenProxiedThenNullEmail() {
        Optional<User> securedUser = users.findByName("name");
        assertThat(securedUser.get().getEmail()).isNull();
    }
    ```

Kotlin

:   ``` kotlin
    @Autowired
    var users:UserRepository? = null

    @Test
    fun getEmailWhenProxiedThenNullEmail() {
        val securedUser: Optional<User> = users.findByName("name")
        assertThat(securedUser.get().getEmail()).isNull()
    }
    ```
:::

## 使用方法调用的拒绝结果 {#_使用方法调用的拒绝结果}

在某些场景中，您可能希望返回一个从拒绝结果派生的安全结果。
例如，如果用户未被授权查看电子邮件地址，您可能希望对原始电子邮件地址应用一些掩码，即
*useremail@example.com* 将变为 *use\*\*\*\*\*\*@example.com*。

对于这些场景，您可以覆盖 `MethodAuthorizationDeniedHandler` 的
`handleDeniedInvocationResult`，该方法将
{security-api-url}org/springframework/security/authorization/method/MethodInvocationResult.html\[`MethodInvocationResult`\]
作为参数。 让我们继续前面的示例，但不是返回
`null`，而是返回电子邮件的掩码值：

::: informalexample

Java

:   ``` java
    public class EmailMaskingMethodAuthorizationDeniedHandler implements MethodAuthorizationDeniedHandler { 

        @Override
        public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
            return "***";
        }

        @Override
        public Object handleDeniedInvocationResult(MethodInvocationResult methodInvocationResult, AuthorizationResult authorizationResult) {
            String email = (String) methodInvocationResult.getResult();
            return email.replaceAll("(^[^@]{3}|(?!^)\\G)[^@]", "$1*");
        }

    }

    @Configuration
    @EnableMethodSecurity
    public class SecurityConfig {

        @Bean 
        public EmailMaskingMethodAuthorizationDeniedHandler emailMaskingMethodAuthorizationDeniedHandler() {
            return new EmailMaskingMethodAuthorizationDeniedHandler();
        }

    }

    public class User {
        // ...

        @PostAuthorize(value = "hasAuthority('user:read')")
        @HandleAuthorizationDenied(handlerClass = EmailMaskingMethodAuthorizationDeniedHandler.class)
        public String getEmail() {
            return this.email;
        }
    }
    ```

Kotlin

:   ``` kotlin
    class EmailMaskingMethodAuthorizationDeniedHandler : MethodAuthorizationDeniedHandler {

        override fun handleDeniedInvocation(methodInvocation: MethodInvocation, authorizationResult: AuthorizationResult): Any {
            return "***"
        }

        override fun handleDeniedInvocationResult(methodInvocationResult: MethodInvocationResult, authorizationResult: AuthorizationResult): Any {
            val email = methodInvocationResult.result as String
            return email.replace("(^[^@]{3}|(?!^)\\G)[^@]".toRegex(), "$1*")
        }

    }

    @Configuration
    @EnableMethodSecurity
    class SecurityConfig {

        @Bean
        fun emailMaskingMethodAuthorizationDeniedHandler(): EmailMaskingMethodAuthorizationDeniedHandler {
            return EmailMaskingMethodAuthorizationDeniedHandler()
        }

    }

    class User (val name:String, @PostAuthorize(value = "hasAuthority('user:read')") @HandleAuthorizationDenied(handlerClass = EmailMaskingMethodAuthorizationDeniedHandler::class) val email:String) 
    ```
:::

- 创建一个返回未经授权结果值的掩码值的
  `MethodAuthorizationDeniedHandler` 实现

- 将 `EmailMaskingMethodAuthorizationDeniedHandler` 注册为 Bean

- 使用 `@HandleAuthorizationDenied` 注解方法并将
  `EmailMaskingMethodAuthorizationDeniedHandler` 传递给 `handlerClass`
  属性

然后，您可以验证返回的是掩码电子邮件而不是 `AccessDeniedException`：

:::: warning
::: title
:::

由于您可以访问原始的拒绝值，请确保正确处理它并且不要将其返回给调用者。
::::

::: informalexample

Java

:   ``` java
    @Autowired
    UserRepository users;

    @Test
    void getEmailWhenProxiedThenMaskedEmail() {
        Optional<User> securedUser = users.findByName("name");
        // email is useremail@example.com
        assertThat(securedUser.get().getEmail()).isEqualTo("use******@example.com");
    }
    ```

Kotlin

:   ``` kotlin
    @Autowired
    var users:UserRepository? = null

    @Test
    fun getEmailWhenProxiedThenMaskedEmail() {
        val securedUser: Optional<User> = users.findByName("name")
        // email is useremail@example.com
        assertThat(securedUser.get().getEmail()).isEqualTo("use******@example.com")
    }
    ```
:::

在实现 `MethodAuthorizationDeniedHandler` 时，您有几个返回类型的选择：

- 一个 `null` 值。

- 一个非空值，尊重方法的返回类型。

- 抛出一个异常，通常是 `AuthorizationDeniedException`
  的实例。这是默认行为。

- 一个 `Mono` 类型用于响应式应用程序。

请注意，由于处理程序必须在您的应用程序上下文中注册为
Bean，如果需要更复杂的逻辑，您可以将依赖项注入其中。
除此之外，您还可以使用 `MethodInvocation` 或 `MethodInvocationResult`
以及 `AuthorizationResult` 获取更多与授权决策相关的详细信息。

## 根据可用参数决定返回什么 {#deciding-return-based-parameters}

考虑一个可能存在多种掩码值的场景，如果我们必须为每个方法创建一个处理程序，效率可能不高，尽管这样做完全可以。
在这种情况下，我们可以使用通过参数传递的信息来决定做什么。
例如，我们可以创建一个自定义的 `@Mask`
注解和一个检测该注解以决定返回什么掩码值的处理程序：

::: informalexample

Java

:   ``` java
    import org.springframework.core.annotation.AnnotationUtils;

    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    public @interface Mask {

        String value();

    }

    public class MaskAnnotationDeniedHandler implements MethodAuthorizationDeniedHandler {

        @Override
        public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
            Mask mask = AnnotationUtils.getAnnotation(methodInvocation.getMethod(), Mask.class);
            return mask.value();
        }

    }

    @Configuration
    @EnableMethodSecurity
    public class SecurityConfig {

        @Bean
        public MaskAnnotationDeniedHandler maskAnnotationDeniedHandler() {
            return new MaskAnnotationDeniedHandler();
        }

    }

    @Component
    public class MyService {

        @PreAuthorize(value = "hasAuthority('user:read')")
        @HandleAuthorizationDenied(handlerClass = MaskAnnotationDeniedHandler.class)
        @Mask("***")
        public String foo() {
            return "foo";
        }

        @PreAuthorize(value = "hasAuthority('user:read')")
        @HandleAuthorizationDenied(handlerClass = MaskAnnotationDeniedHandler.class)
        @Mask("???")
        public String bar() {
            return "bar";
        }

    }
    ```

Kotlin

:   ``` kotlin
    import org.springframework.core.annotation.AnnotationUtils

    @Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
    @Retention(AnnotationRetention.RUNTIME)
    annotation class Mask(val value: String)

    class MaskAnnotationDeniedHandler : MethodAuthorizationDeniedHandler {

        override fun handleDeniedInvocation(methodInvocation: MethodInvocation, authorizationResult: AuthorizationResult): Any {
            val mask = AnnotationUtils.getAnnotation(methodInvocation.method, Mask::class.java)
            return mask.value
        }

    }

    @Configuration
    @EnableMethodSecurity
    class SecurityConfig {

        @Bean
        fun maskAnnotationDeniedHandler(): MaskAnnotationDeniedHandler {
            return MaskAnnotationDeniedHandler()
        }

    }

    @Component
    class MyService {

        @PreAuthorize(value = "hasAuthority('user:read')")
        @HandleAuthorizationDenied(handlerClass = MaskAnnotationDeniedHandler::class)
        @Mask("***")
        fun foo(): String {
            return "foo"
        }

        @PreAuthorize(value = "hasAuthority('user:read')")
        @HandleAuthorizationDenied(handlerClass = MaskAnnotationDeniedHandler::class)
        @Mask("???")
        fun bar(): String {
            return "bar"
        }

    }
    ```
:::

现在，当访问被拒绝时，返回值将基于 `@Mask` 注解决定：

::: informalexample

Java

:   ``` java
    @Autowired
    MyService myService;

    @Test
    void fooWhenDeniedThenReturnStars() {
        String value = this.myService.foo();
        assertThat(value).isEqualTo("***");
    }

    @Test
    void barWhenDeniedThenReturnQuestionMarks() {
        String value = this.myService.foo();
        assertThat(value).isEqualTo("???");
    }
    ```

Kotlin

:   ``` kotlin
    @Autowired
    var myService: MyService

    @Test
    fun fooWhenDeniedThenReturnStars() {
        val value: String = myService.foo()
        assertThat(value).isEqualTo("***")
    }

    @Test
    fun barWhenDeniedThenReturnQuestionMarks() {
        val value: String = myService.foo()
        assertThat(value).isEqualTo("???")
    }
    ```
:::

## 与元注解支持结合 {#_与元注解支持结合}

您还可以将 `@HandleAuthorizationDenied`
与其他注解结合，以减少和简化方法中的注解。 让我们考虑
[前一节的示例](#deciding-return-based-parameters) 并将
`@HandleAuthorizationDenied` 与 `@Mask` 合并：

::: informalexample

Java

:   ``` java
    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @HandleAuthorizationDenied(handlerClass = MaskAnnotationDeniedHandler.class)
    public @interface Mask {

        String value();

    }

    @Mask("***")
    public String myMethod() {
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
    @Retention(AnnotationRetention.RUNTIME)
    @HandleAuthorizationDenied(handlerClass = MaskAnnotationDeniedHandler::class)
    annotation class Mask(val value: String)

    @Mask("***")
    fun myMethod(): String {
        // ...
    }
    ```
:::

现在，当您的方法需要掩码行为时，您不必记住同时添加这两个注解。
请务必阅读 [元注解支持](#meta-annotations) 部分以获取更多使用详情。

# 从 `@EnableGlobalMethodSecurity` 迁移 {#migration-enableglobalmethodsecurity}

如果您正在使用 `@EnableGlobalMethodSecurity`，则应迁移到
`@EnableMethodSecurity`。

## 将 [全局方法安全](servlet/authorization/method-security.xml#jc-enable-global-method-security) 替换为 [方法安全](servlet/authorization/method-security.xml#jc-enable-method-security) {#servlet-replace-globalmethodsecurity-with-methodsecurity}

{security-api-url}org/springframework/security/config/annotation/method/configuration/EnableGlobalMethodSecurity.html\[`@EnableGlobalMethodSecurity`\]
和
[`<global-method-security>`](servlet/appendix/namespace/method-security.xml#nsa-global-method-security)
已弃用，取而代之的是
{security-api-url}org/springframework/security/config/annotation/method/configuration/EnableMethodSecurity.html\[`@EnableMethodSecurity`\]
和
[`<method-security>`](servlet/appendix/namespace/method-security.xml#nsa-method-security)。
新注解和 XML 元素默认激活 Spring 的
[预后注解](servlet/authorization/method-security.xml#jc-enable-method-security)，并在内部使用
`AuthorizationManager`。

这意味着以下两个列表在功能上是等效的：

::: informalexample

Java

:   ``` java
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    ```

Kotlin

:   ``` kotlin
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    ```

Xml

:   ``` xml
    <global-method-security pre-post-enabled="true"/>
    ```
:::

和：

::: informalexample

Java

:   ``` java
    @EnableMethodSecurity
    ```

Kotlin

:   ``` kotlin
    @EnableMethodSecurity
    ```

Xml

:   ``` xml
    <method-security/>
    ```
:::

对于不使用预后注解的应用程序，请确保将其关闭以避免激活不需要的行为。

例如，像这样的列表：

::: informalexample

Java

:   ``` java
    @EnableGlobalMethodSecurity(securedEnabled = true)
    ```

Kotlin

:   ``` kotlin
    @EnableGlobalMethodSecurity(securedEnabled = true)
    ```

Xml

:   ``` xml
    <global-method-security secured-enabled="true"/>
    ```
:::

应更改为：

::: informalexample

Java

:   ``` java
    @EnableMethodSecurity(securedEnabled = true, prePostEnabled = false)
    ```

Kotlin

:   ``` kotlin
    @EnableMethodSecurity(securedEnabled = true, prePostEnabled = false)
    ```

Xml

:   ``` xml
    <method-security secured-enabled="true" pre-post-enabled="false"/>
    ```
:::

## 使用自定义 `@Bean` 而不是子类化 `DefaultMethodSecurityExpressionHandler` {#_使用自定义_bean_而不是子类化_defaultmethodsecurityexpressionhandler}

作为一种性能优化，`MethodSecurityExpressionHandler`
引入了一个新方法，该方法接受 `Supplier<Authentication>` 而不是
`Authentication`。

这允许 Spring Security 延迟查找 `Authentication`，并且当您使用
`@EnableMethodSecurity` 而不是 `@EnableGlobalMethodSecurity`
时会自动利用这一点。

然而，假设您的代码扩展了 `DefaultMethodSecurityExpressionHandler`
并重写了
`createSecurityExpressionRoot(Authentication, MethodInvocation)`
以返回自定义的 `SecurityExpressionRoot` 实例。 这将不再起作用，因为
`@EnableMethodSecurity` 设置的安排调用了
`createEvaluationContext(Supplier<Authentication>, MethodInvocation)`
而不是。

幸运的是，这种级别的定制通常没有必要。
相反，您可以创建一个具有所需授权方法的自定义 Bean。

例如，假设您想要自定义评估 `@PostAuthorize("hasAuthority('ADMIN')")`。
您可以创建一个像这样的自定义 `@Bean`：

::: informalexample

Java

:   ``` java
    class MyAuthorizer {
        boolean isAdmin(MethodSecurityExpressionOperations root) {
            boolean decision = root.hasAuthority("ADMIN");
            // custom work ...
            return decision;
        }
    }
    ```

Kotlin

:   ``` kotlin
    class MyAuthorizer {
        fun isAdmin(val root: MethodSecurityExpressionOperations): boolean {
            val decision = root.hasAuthority("ADMIN");
            // custom work ...
            return decision;
        }
    }
    ```
:::

然后在注解中像这样引用它：

::: informalexample

Java

:   ``` java
    @PreAuthorize("@authz.isAdmin(#root)")
    ```

Kotlin

:   ``` kotlin
    @PreAuthorize("@authz.isAdmin(#root)")
    ```
:::

### 我仍然更喜欢子类化 `DefaultMethodSecurityExpressionHandler` {#subclass-defaultmethodsecurityexpressionhandler}

如果您必须继续子类化
`DefaultMethodSecurityExpressionHandler`，您仍然可以这样做。
相反，像这样重写
`createEvaluationContext(Supplier<Authentication>, MethodInvocation)`
方法：

::: informalexample

Java

:   ``` java
    @Component
    class MyExpressionHandler extends DefaultMethodSecurityExpressionHandler {
        @Override
        public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation mi) {
            StandardEvaluationContext context = (StandardEvaluationContext) super.createEvaluationContext(authentication, mi);
            MethodSecurityExpressionOperations delegate = (MethodSecurityExpressionOperations) context.getRootObject().getValue();
            MySecurityExpressionRoot root = new MySecurityExpressionRoot(delegate);
            context.setRootObject(root);
            return context;
        }
    }
    ```

Kotlin

:   ``` kotlin
    @Component
    class MyExpressionHandler: DefaultMethodSecurityExpressionHandler {
        override fun createEvaluationContext(val authentication: Supplier<Authentication>,
            val mi: MethodInvocation): EvaluationContext {
            val context = super.createEvaluationContext(authentication, mi) as StandardEvaluationContext
            val delegate = context.getRootObject().getValue() as MethodSecurityExpressionOperations
            val root = MySecurityExpressionRoot(delegate)
            context.setRootObject(root)
            return context
        }
    }
    ```
:::

# 进一步阅读 {#_进一步阅读}

现在您已经保护了应用程序的请求，请
[保护其请求](servlet/authorization/authorize-http-requests.xml)（如果尚未完成）。
您还可以进一步阅读 [测试您的应用程序](servlet/test/index.xml) 或集成
Spring Security 与其他应用程序方面，如
[数据层](servlet/integrations/data.xml) 或
[跟踪和指标](servlet/integrations/observability.xml)。
