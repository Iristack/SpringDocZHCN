本节演示了如何使用 Spring Security
的测试支持来测试基于方法的安全性。我们首先引入一个
`MessageService`，该服务要求用户必须经过身份验证才能访问：

::: informalexample

Java

:   ``` java
    public class HelloMessageService implements MessageService {

        @PreAuthorize("authenticated")
        public String getMessage() {
            Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();
            return "Hello " + authentication;
        }
    }
    ```

Kotlin

:   ``` kotlin
    class HelloMessageService : MessageService {
        @PreAuthorize("authenticated")
        fun getMessage(): String {
            val authentication: Authentication = SecurityContextHolder.getContext().authentication
            return "Hello $authentication"
        }
    }
    ```
:::

`getMessage` 方法的返回结果是一个字符串，内容为对当前 Spring Security
`Authentication` 对象的问候 "Hello"。以下列出了示例输出：

``` text
Hello org.springframework.security.authentication.UsernamePasswordAuthenticationToken@ca25360: Principal: org.springframework.security.core.userdetails.User@36ebcb: Username: user; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER; Credentials: [PROTECTED]; Authenticated: true; Details: null; Granted Authorities: ROLE_USER
```

# 安全性测试设置 {#test-method-setup}

在使用 Spring Security 的测试支持之前，我们必须先进行一些配置：

::: informalexample

Java

:   ``` java
    @ExtendWith(SpringExtension.class) 
    @ContextConfiguration 
    public class WithMockUserTests {
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration
    class WithMockUserTests {
        // ...
    }
    ```
:::

- `@ExtendWith` 指示 spring-test 模块创建一个
  `ApplicationContext`。更多详细信息，请参阅
  {spring-framework-reference-url}testing.html#testcontext-junit-jupiter-extension\[Spring
  参考文档\]。

- `@ContextConfiguration` 告诉 spring-test 使用哪些配置来创建
  `ApplicationContext`。由于未指定具体配置，将尝试默认的配置位置。这与使用现有的
  Spring 测试支持并无区别。更多信息请参考
  {spring-framework-reference-url}testing.html#spring-testing-annotation-contextconfiguration\[Spring
  参考文档\]。

:::: note
::: title
:::

Spring Security 通过 `WithSecurityContextTestExecutionListener` 集成到
Spring Test
支持中，确保我们的测试以正确的用户身份运行。它会在运行测试前填充
`SecurityContextHolder`。如果你使用响应式方法安全（reactive method
security），还需要 `ReactorContextTestExecutionListener` 来填充
`ReactiveSecurityContextHolder`。测试完成后，会清除
`SecurityContextHolder`。如果只需要 Spring Security 相关的支持，你可以用
`@SecurityTestExecutionListeners` 替代 `@ContextConfiguration`。
::::

记住，我们在 `HelloMessageService` 上添加了 `@PreAuthorize`
注解，因此调用该方法需要用户已认证。如果我们运行以下测试，预期它会抛出异常并成功通过：

::: informalexample

Java

:   ``` java
    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void getMessageUnauthenticated() {
        messageService.getMessage();
    }
    ```

Kotlin

:   ``` kotlin
    @Test(expected = AuthenticationCredentialsNotFoundException::class)
    fun getMessageUnauthenticated() {
        messageService.getMessage()
    }
    ```
:::

# \@WithMockUser {#test-method-withmockuser}

问题是："如何最简便地以特定用户身份运行测试？" 答案是使用
`@WithMockUser`。下面的测试将以用户名为 \"user\"、密码为
\"password\"、角色为 \"ROLE_USER\" 的用户身份运行：

::: informalexample

Java

:   ``` java
    @Test
    @WithMockUser
    public void getMessageWithMockUser() {
        String message = messageService.getMessage();
        ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithMockUser
    fun getMessageWithMockUser() {
        val message: String = messageService.getMessage()
        // ...
    }
    ```
:::

具体来说，以下条件成立：

- 用户名 `user` 的用户无需真实存在，因为我们模拟了用户对象。

- 被填充到 `SecurityContext` 中的 `Authentication` 是
  `UsernamePasswordAuthenticationToken` 类型。

- `Authentication` 的主体（principal）是 Spring Security 的 `User`
  对象。

- 该 `User` 的用户名是 `user`。

- 该 `User` 的密码是 `password`。

- 包含一个名为 `ROLE_USER` 的 `GrantedAuthority`。

上述示例很方便，因为它允许我们使用许多默认值。如果我们想以不同的用户名运行测试怎么办？以下测试将以用户名
`customUser` 运行（同样，该用户不需要实际存在）：

::: informalexample

Java

:   ``` java
    @Test
    @WithMockUser("customUsername")
    public void getMessageWithMockUserCustomUsername() {
        String message = messageService.getMessage();
        ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithMockUser("customUsername")
    fun getMessageWithMockUserCustomUsername() {
        val message: String = messageService.getMessage()
        // ...
    }
    ```
:::

我们也可以轻松自定义角色。例如，以下测试将以用户名 `admin` 并拥有
`ROLE_USER` 和 `ROLE_ADMIN` 角色的身份调用：

::: informalexample

Java

:   ``` java
    @Test
    @WithMockUser(username="admin",roles={"USER","ADMIN"})
    public void getMessageWithMockUserCustomUser() {
        String message = messageService.getMessage();
        ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithMockUser(username="admin",roles=["USER","ADMIN"])
    fun getMessageWithMockUserCustomUser() {
        val message: String = messageService.getMessage()
        // ...
    }
    ```
:::

如果我们不希望值自动加上 `ROLE_` 前缀，可以使用 `authorities`
属性。例如，以下测试将以用户名 `admin` 并具有 `USER` 和 `ADMIN`
权限（而非角色）的身份调用：

::: informalexample

Java

:   ``` java
    @Test
    @WithMockUser(username = "admin", authorities = { "ADMIN", "USER" })
    public void getMessageWithMockUserCustomAuthorities() {
        String message = messageService.getMessage();
        ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithMockUser(username = "admin", authorities = ["ADMIN", "USER"])
    fun getMessageWithMockUserCustomUsername() {
        val message: String = messageService.getMessage()
        // ...
    }
    ```
:::

每次都在每个测试方法上放置注解可能会有些繁琐。相反，我们可以将注解放在类级别上，这样每个测试都会使用指定的用户。以下示例中，所有测试都使用用户名为
`admin`、密码为 `password`、且拥有 `ROLE_USER` 和 `ROLE_ADMIN`
角色的用户运行：

::: informalexample

Java

:   ``` java
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration
    @WithMockUser(username="admin",roles={"USER","ADMIN"})
    public class WithMockUserTests {
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration
    @WithMockUser(username="admin",roles=["USER","ADMIN"])
    class WithMockUserTests {
        // ...
    }
    ```
:::

如果你使用 JUnit 5 的 `@Nested`
嵌套测试功能，还可以将注解放在外层类上，使其应用于所有嵌套类。以下示例中，两个测试套件的所有测试都将使用用户名为
`admin`、密码为 `password`、并具有 `ROLE_USER` 和 `ROLE_ADMIN`
角色的用户运行：

::: informalexample

Java

:   ``` java
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration
    @WithMockUser(username="admin",roles={"USER","ADMIN"})
    public class WithMockUserTests {

        @Nested
        public class TestSuite1 {
            // ... 所有测试方法均使用 admin 用户
        }

        @Nested
        public class TestSuite2 {
            // ... 所有测试方法均使用 admin 用户
        }
    }
    ```

Kotlin

:   ``` kotlin
    @ExtendWith(SpringExtension::class)
    @ContextConfiguration
    @WithMockUser(username = "admin", roles = ["USER", "ADMIN"])
    class WithMockUserTests {
        @Nested
        inner class TestSuite1 { // ... 所有测试方法均使用 admin 用户
        }

        @Nested
        inner class TestSuite2 { // ... 所有测试方法均使用 admin 用户
        }
    }
    ```
:::

默认情况下，`SecurityContext` 在
`TestExecutionListener.beforeTestMethod` 事件期间设置，相当于发生在
JUnit 的 `@Before` 注解之前。你也可以将其更改为在
`TestExecutionListener.beforeTestExecution` 事件期间设置，即在 JUnit 的
`@Before` 之后但在测试方法调用之前：

``` java
@WithMockUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```

# \@WithAnonymousUser {#test-method-withanonymoususer}

使用 `@WithAnonymousUser`
允许以匿名用户身份运行测试。当你希望大多数测试使用特定用户，但少数测试需要以匿名用户运行时，这特别方便。以下示例展示了
`withMockUser1` 和 `withMockUser2` 使用
[\@WithMockUser](#test-method-withmockuser)，而 `anonymous`
则作为匿名用户运行：

::: informalexample

Java

:   ``` java
    @ExtendWith(SpringExtension.class)
    @WithMockUser
    public class WithUserClassLevelAuthenticationTests {

        @Test
        public void withMockUser1() {
        }

        @Test
        public void withMockUser2() {
        }

        @Test
        @WithAnonymousUser
        public void anonymous() throws Exception {
            // 覆盖默认设置，以匿名用户身份运行
        }
    }
    ```

Kotlin

:   ``` kotlin
    @ExtendWith(SpringExtension.class)
    @WithMockUser
    class WithUserClassLevelAuthenticationTests {
        @Test
        fun withMockUser1() {
        }

        @Test
        fun withMockUser2() {
        }

        @Test
        @WithAnonymousUser
        fun anonymous() {
            // 覆盖默认设置，以匿名用户身份运行
        }
    }
    ```
:::

默认情况下，`SecurityContext` 在
`TestExecutionListener.beforeTestMethod` 事件期间设置，相当于发生在
JUnit 的 `@Before` 之前。你可以将其更改为在
`TestExecutionListener.beforeTestExecution` 事件期间设置，即在 JUnit 的
`@Before` 之后但在测试方法调用之前：

``` java
@WithAnonymousUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```

# \@WithUserDetails {#test-method-withuserdetails}

虽然 `@WithMockUser`
是入门的好方法，但它并不适用于所有情况。例如，某些应用程序期望
`Authentication` 的 principal
是特定类型。这样做是为了让应用程序能够引用自定义类型的
principal，从而减少对 Spring Security 的耦合。

这种自定义的 principal 通常由一个自定义的 `UserDetailsService`
返回，该服务返回一个同时实现 `UserDetails`
和自定义类型的对象。对于这种情况，通过自定义 `UserDetailsService`
创建测试用户非常有用。这正是 `@WithUserDetails` 所做的事情。

假设我们有一个作为 Bean 暴露的 `UserDetailsService`，以下测试将以
`UsernamePasswordAuthenticationToken` 类型的 `Authentication`
调用，并且其 principal 是从 `UserDetailsService` 中查找用户名为 `user`
的用户所返回的对象：

::: informalexample

Java

:   ``` java
    @Test
    @WithUserDetails
    public void getMessageWithUserDetails() {
        String message = messageService.getMessage();
        ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithUserDetails
    fun getMessageWithUserDetails() {
        val message: String = messageService.getMessage()
        // ...
    }
    ```
:::

我们还可以自定义用于从 `UserDetailsService`
查找用户的用户名。例如，此测试将以从 `UserDetailsService` 中查找用户名为
`customUsername` 的 principal 运行：

::: informalexample

Java

:   ``` java
    @Test
    @WithUserDetails("customUsername")
    public void getMessageWithUserDetailsCustomUsername() {
        String message = messageService.getMessage();
        ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithUserDetails("customUsername")
    fun getMessageWithUserDetailsCustomUsername() {
        val message: String = messageService.getMessage()
        // ...
    }
    ```
:::

我们还可以显式提供 `UserDetailsService` 的 Bean 名称。以下测试使用名为
`myUserDetailsService` 的 `UserDetailsService` 查找用户名为
`customUsername` 的用户：

::: informalexample

Java

:   ``` java
    @Test
    @WithUserDetails(value="customUsername", userDetailsServiceBeanName="myUserDetailsService")
    public void getMessageWithUserDetailsServiceBeanName() {
        String message = messageService.getMessage();
        ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithUserDetails(value="customUsername", userDetailsServiceBeanName="myUserDetailsService")
    fun getMessageWithUserDetailsServiceBeanName() {
        val message: String = messageService.getMessage()
        // ...
    }
    ```
:::

正如我们对 `@WithMockUser`
所做的那样，我们也可以将注解放在类级别，使每个测试都使用相同的用户。但是，与
`@WithMockUser` 不同的是，`@WithUserDetails` 要求该用户必须真实存在。

默认情况下，`SecurityContext` 在
`TestExecutionListener.beforeTestMethod` 事件期间设置，相当于发生在
JUnit 的 `@Before` 之前。你可以将其更改为在
`TestExecutionListener.beforeTestExecution` 事件期间设置，即在 JUnit 的
`@Before` 之后但在测试方法调用之前：

``` java
@WithUserDetails(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```

# \@WithSecurityContext {#test-method-withsecuritycontext}

我们已经看到，如果未使用自定义的 `Authentication`
principal，`@WithMockUser`
是一个极佳的选择。接着我们发现，`@WithUserDetails` 允许我们使用自定义的
`UserDetailsService` 来创建 `Authentication`
principal，但要求用户必须存在。现在我们来看一种灵活性最高的选项。

我们可以创建自己的注解，并使用 `@WithSecurityContext` 来构建任意所需的
`SecurityContext`。例如，我们可以创建一个名为 `@WithMockCustomUser`
的注解：

::: informalexample

Java

:   ``` java
    @Retention(RetentionPolicy.RUNTIME)
    @WithSecurityContext(factory = WithMockCustomUserSecurityContextFactory.class)
    public @interface WithMockCustomUser {

        String username() default "rob";

        String name() default "Rob Winch";
    }
    ```

Kotlin

:   ``` kotlin
    @Retention(AnnotationRetention.RUNTIME)
    @WithSecurityContext(factory = WithMockCustomUserSecurityContextFactory::class)
    annotation class WithMockCustomUser(val username: String = "rob", val name: String = "Rob Winch")
    ```
:::

可以看到，`@WithMockCustomUser` 使用了 `@WithSecurityContext` 注解。这向
Spring Security 测试支持表明我们打算为测试创建一个
`SecurityContext`。`@WithSecurityContext` 注解要求我们指定一个
`SecurityContextFactory`，以便根据我们的 `@WithMockCustomUser`
注解创建新的 `SecurityContext`。以下是
`WithMockCustomUserSecurityContextFactory` 的实现：

::: informalexample

Java

:   ``` java
    public class WithMockCustomUserSecurityContextFactory
        implements WithSecurityContextFactory<WithMockCustomUser> {
        @Override
        public SecurityContext createSecurityContext(WithMockCustomUser customUser) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();

            CustomUserDetails principal =
                new CustomUserDetails(customUser.name(), customUser.username());
            Authentication auth =
                UsernamePasswordAuthenticationToken.authenticated(principal, "password", principal.getAuthorities());
            context.setAuthentication(auth);
            return context;
        }
    }
    ```

Kotlin

:   ``` kotlin
    class WithMockCustomUserSecurityContextFactory : WithSecurityContextFactory<WithMockCustomUser> {
        override fun createSecurityContext(customUser: WithMockCustomUser): SecurityContext {
            val context = SecurityContextHolder.createEmptyContext()
            val principal = CustomUserDetails(customUser.name, customUser.username)
            val auth: Authentication =
                UsernamePasswordAuthenticationToken(principal, "password", principal.authorities)
            context.authentication = auth
            return context
        }
    }
    ```
:::

现在，我们可以将新注解用于测试类或测试方法上，配合 Spring Security 的
`WithSecurityContextTestExecutionListener`，确保 `SecurityContext`
被正确填充。

在创建自己的 `WithSecurityContextFactory`
实现时，值得注意的是它们可以使用标准的 Spring
注解。例如，`WithUserDetailsSecurityContextFactory` 使用 `@Autowired`
注解来获取 `UserDetailsService`：

::: informalexample

Java

:   ``` java
    final class WithUserDetailsSecurityContextFactory
        implements WithSecurityContextFactory<WithUserDetails> {

        private UserDetailsService userDetailsService;

        @Autowired
        public WithUserDetailsSecurityContextFactory(UserDetailsService userDetailsService) {
            this.userDetailsService = userDetailsService;
        }

        public SecurityContext createSecurityContext(WithUserDetails withUser) {
            String username = withUser.value();
            Assert.hasLength(username, "value() must be non-empty String");
            UserDetails principal = userDetailsService.loadUserByUsername(username);
            Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(principal, principal.getPassword(), principal.getAuthorities());
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            return context;
        }
    }
    ```

Kotlin

:   ``` kotlin
    class WithUserDetailsSecurityContextFactory @Autowired constructor(private val userDetailsService: UserDetailsService) :
        WithSecurityContextFactory<WithUserDetails> {
        override fun createSecurityContext(withUser: WithUserDetails): SecurityContext {
            val username: String = withUser.value
            Assert.hasLength(username, "value() must be non-empty String")
            val principal = userDetailsService.loadUserByUsername(username)
            val authentication: Authentication =
                UsernamePasswordAuthenticationToken(principal, principal.password, principal.authorities)
            val context = SecurityContextHolder.createEmptyContext()
            context.authentication = authentication
            return context
        }
    }
    ```
:::

默认情况下，`SecurityContext` 在
`TestExecutionListener.beforeTestMethod` 事件期间设置，相当于发生在
JUnit 的 `@Before` 之前。你可以将其更改为在
`TestExecutionListener.beforeTestExecution` 事件期间设置，即在 JUnit 的
`@Before` 之后但在测试方法调用之前：

``` java
@WithSecurityContext(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```

# 测试元注解 {#test-method-meta-annotations}

如果你在测试中频繁重复使用相同用户，则每次都必须指定属性，这是不理想的。例如，如果你有许多测试涉及用户名为
`admin`、角色为 `ROLE_USER` 和 `ROLE_ADMIN` 的管理员用户，你就得反复写：

::: informalexample

Java

:   ``` java
    @WithMockUser(username="admin",roles={"USER","ADMIN"})
    ```

Kotlin

:   ``` kotlin
    @WithMockUser(username="admin",roles=["USER","ADMIN"])
    ```
:::

为了避免到处重复这些代码，我们可以使用元注解（meta
annotation）。例如，我们可以创建一个名为 `WithMockAdmin` 的元注解：

::: informalexample

Java

:   ``` java
    @Retention(RetentionPolicy.RUNTIME)
    @WithMockUser(value="rob",roles="ADMIN")
    public @interface WithMockAdmin { }
    ```

Kotlin

:   ``` kotlin
    @Retention(AnnotationRetention.RUNTIME)
    @WithMockUser(value = "rob", roles = ["ADMIN"])
    annotation class WithMockAdmin
    ```
:::

现在我们可以像使用冗长版本的 `@WithMockUser` 一样使用 `@WithMockAdmin`。

元注解适用于上面介绍的任何测试注解。例如，这意味着我们也可以为
`@WithUserDetails("admin")` 创建一个元注解。
