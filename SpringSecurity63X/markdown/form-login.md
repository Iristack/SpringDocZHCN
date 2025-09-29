你可以轻松地创建一个请求，使用 Spring Security
的测试支持来测试基于表单的身份认证。 例如，以下 `formLogin`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)
将会向 \"/login\" 发送一个 POST 请求，其中包含用户名 \"user\"、密码
\"password\" 以及一个有效的 CSRF 令牌：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin())
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin())
    ```
:::

该请求很容易进行自定义。 例如，下面的代码将向 \"/auth\" 发送一个 POST
请求，用户名为 \"admin\"，密码为 \"pass\"，并附带一个有效的 CSRF 令牌：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin("/auth").user("admin").password("pass"))
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin("/auth").user("admin").password("pass"))
    ```
:::

我们还可以自定义用于传递用户名和密码的参数名称。
例如，下面的请求将用户名通过 HTTP 参数 \"u\" 传递，密码通过 HTTP 参数
\"p\" 传递：

::: informalexample

Java

:   ``` java
    mvc
        .perform(formLogin("/auth").user("u","admin").password("p","pass"))
    ```

Kotlin

:   ``` kotlin
    mvc
        .perform(formLogin("/auth").user("u","admin").password("p","pass"))
    ```
:::
