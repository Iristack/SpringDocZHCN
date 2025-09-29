有时我们需要对请求的结果做出各种与安全相关的断言。
为了满足这一需求，Spring Security Test 提供了对 Spring MVC Test 的
`ResultMatcher` 接口的实现。 要使用 Spring Security 的 `ResultMatcher`
实现，请确保使用以下静态导入：

::: informalexample

Java

:   ``` java
    import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*
    ```
:::

# 未认证断言（Unauthenticated Assertion） {#_未认证断言unauthenticated_assertion}

有时候，我们可能希望断言在一次 `MockMvc`
调用结果中没有关联已认证的用户。
例如，你可能想测试提交一个无效的用户名和密码，并验证是否没有任何用户被认证。
你可以通过 Spring Security 的测试支持轻松实现这一点，示例如下：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin().password("invalid"))
        .andExpect(unauthenticated());
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin().password("invalid"))
        .andExpect { unauthenticated() }
    ```
:::

# 已认证断言（Authenticated Assertion） {#_已认证断言authenticated_assertion}

很多时候我们需要断言存在一个已认证的用户。
例如，我们可能想要验证认证是否成功。
我们可以使用如下代码片段来验证基于表单的登录是否成功：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin())
        .andExpect(authenticated());
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin())
        .andExpect { authenticated() }
    ```
:::

如果我们还想断言用户的权限角色（roles），可以改进前面的代码，如下所示：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin().user("admin"))
        .andExpect(authenticated().withRoles("USER","ADMIN"));
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin().user("admin"))
        .andExpect { authenticated().withRoles("USER","ADMIN") }
    ```
:::

或者，我们可以验证用户名：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin().user("admin"))
        .andExpect(authenticated().withUsername("admin"));
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin().user("admin"))
        .andExpect { authenticated().withUsername("admin") }
    ```
:::

我们也可以组合多个断言：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin().user("admin"))
        .andExpect(authenticated().withUsername("admin").withRoles("USER", "ADMIN"));
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin().user("admin"))
        .andExpect { authenticated().withUsername("admin").withRoles("USER", "ADMIN") }
    ```
:::

此外，我们还可以对认证对象进行自定义断言：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin())
        .andExpect(authenticated().withAuthentication(auth ->
            assertThat(auth).isInstanceOf(UsernamePasswordAuthenticationToken.class)));
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin())
        .andExpect {
            authenticated().withAuthentication { auth ->
                assertThat(auth).isInstanceOf(UsernamePasswordAuthenticationToken::class.java) }
            }
        }
    ```
:::
