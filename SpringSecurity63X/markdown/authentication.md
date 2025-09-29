通常希望以特定用户的身份来运行测试。有以下两种简单的方法可以为测试设置用户信息：

- [使用 RequestPostProcessor 在 Spring MVC
  测试中以用户身份运行](#test-mockmvc-securitycontextholder-rpp)

- [使用注解在 Spring MVC
  测试中以用户身份运行](#running-as-a-user-in-spring-mvc-test-with-annotations)

# 使用 RequestPostProcessor 在 Spring MVC 测试中以用户身份运行 {#test-mockmvc-securitycontextholder-rpp}

你可以通过多种方式将用户与当前的 `HttpServletRequest`
关联起来。以下示例展示了如何以用户名为 `user`、密码为 `password`、角色为
`ROLE_USER` 的用户身份运行（该用户无需真实存在）：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/").with(user("user")))
    ```

Kotlin

:   ``` kotlin
    mvc.get("/") {
        with(user("user"))
    }
    ```
:::

:::: note
::: title
:::

该功能通过将用户信息与 `HttpServletRequest` 关联实现。为了将请求与
`SecurityContextHolder` 关联，你需要确保
`SecurityContextPersistenceFilter` 已被注册到 `MockMvc`
实例中。可以通过以下几种方式实现：

- 调用
  [`apply(springSecurity())`](servlet/test/mockmvc/setup.xml#test-mockmvc-setup)

- 将 Spring Security 的 `FilterChainProxy` 添加到 `MockMvc`

- 当使用 `MockMvcBuilders.standaloneSetup` 时，手动添加
  `SecurityContextPersistenceFilter` 到 `MockMvc` 实例中可能是合适的选择
::::

你可以轻松进行自定义配置。例如，下面的代码将以用户名 \"admin\"、密码
\"pass\"、角色为 \"ROLE_USER\" 和 \"ROLE_ADMIN\"
的用户身份运行（该用户无需真实存在）：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/admin").with(user("admin").password("pass").roles("USER","ADMIN")))
    ```

Kotlin

:   ``` kotlin
    mvc.get("/admin") {
        with(user("admin").password("pass").roles("USER","ADMIN"))
    }
    ```
:::

如果你有一个自定义的 `UserDetails`
对象并希望使用它，也可以轻松指定。例如，以下代码将使用指定的
`UserDetails`（无需真实存在）创建一个
`UsernamePasswordAuthenticationToken`，其主体（principal）为该
`UserDetails`：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/").with(user(userDetails)))
    ```

Kotlin

:   ``` kotlin
    mvc.get("/") {
        with(user(userDetails))
    }
    ```
:::

你也可以以匿名用户身份运行测试，如下所示：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/").with(anonymous()))
    ```

Kotlin

:   ``` kotlin
    mvc.get("/") {
        with(anonymous())
    }
    ```
:::

当你默认使用某个用户运行测试，但希望某些请求以匿名用户身份处理时，这种方式特别有用。

如果你想使用自定义的 `Authentication`
对象（无需真实存在），也可以这样做：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/").with(authentication(authentication)))
    ```

Kotlin

:   ``` kotlin
    mvc.get("/") {
        with(authentication(authentication))
    }
    ```
:::

甚至还可以直接自定义 `SecurityContext`：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/").with(securityContext(securityContext)))
    ```

Kotlin

:   ``` kotlin
    mvc.get("/") {
        with(securityContext(securityContext))
    }
    ```
:::

我们还可以通过 `MockMvcBuilders`
的默认请求设置，使每个请求都以特定用户身份运行。例如，以下代码将使所有请求以用户名为
\"admin\"、密码为 \"password\"、角色为 \"ROLE_ADMIN\" 的用户身份运行：

::: informalexample

Java

:   ``` java
    mvc = MockMvcBuilders
            .webAppContextSetup(context)
            .defaultRequest(get("/").with(user("user").roles("ADMIN")))
            .apply(springSecurity())
            .build();
    ```

Kotlin

:   ``` kotlin
    mvc = MockMvcBuilders
        .webAppContextSetup(context)
        .defaultRequest<DefaultMockMvcBuilder>(get("/").with(user("user").roles("ADMIN")))
        .apply<DefaultMockMvcBuilder>(springSecurity())
        .build()
    ```
:::

如果你发现多个测试中重复使用相同的用户配置，建议将其封装成一个方法。例如，你可以在名为
`CustomSecurityMockMvcRequestPostProcessors` 的类中定义如下方法：

::: informalexample

Java

:   ``` java
    public static RequestPostProcessor rob() {
        return user("rob").roles("ADMIN");
    }
    ```

Kotlin

:   ``` kotlin
    fun rob(): RequestPostProcessor {
        return user("rob").roles("ADMIN")
    }
    ```
:::

然后在测试中静态导入 `CustomSecurityMockMvcRequestPostProcessors`
并使用该方法：

::: informalexample

Java

:   ``` java
    import static sample.CustomSecurityMockMvcRequestPostProcessors.*;

    ...

    mvc
        .perform(get("/").with(rob()))
    ```

Kotlin

:   ``` kotlin
    import sample.CustomSecurityMockMvcRequestPostProcessors.*

    //...

    mvc.get("/") {
        with(rob())
    }
    ```
:::

# 使用注解在 Spring MVC 测试中以用户身份运行 {#test-mockmvc-withmockuser}

除了使用 `RequestPostProcessor` 创建用户外，你还可以使用
[测试方法安全性](servlet/test/method.xml)
中描述的注解。例如，以下测试将以用户名为 \"user\"、密码为
\"password\"、角色为 \"ROLE_USER\" 的用户身份运行：

::: informalexample

Java

:   ``` java
    @Test
    @WithMockUser
    public void requestProtectedUrlWithUser() throws Exception {
    mvc
            .perform(get("/"))
            ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithMockUser
    fun requestProtectedUrlWithUser() {
        mvc
            .get("/")
            // ...
    }
    ```
:::

或者，以下示例将以用户名为 \"user\"、密码为 \"password\"、角色为
\"ROLE_ADMIN\" 的用户身份运行测试：

::: informalexample

Java

:   ``` java
    @Test
    @WithMockUser(roles="ADMIN")
    public void requestProtectedUrlWithUser() throws Exception {
    mvc
            .perform(get("/"))
            ...
    }
    ```

Kotlin

:   ``` kotlin
    @Test
    @WithMockUser(roles = ["ADMIN"])
    fun requestProtectedUrlWithUser() {
        mvc
            .get("/")
            // ...
    }
    ```
:::
