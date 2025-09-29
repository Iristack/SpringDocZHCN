当测试任何非安全的 HTTP 方法并使用 Spring Security 的 CSRF
保护时，必须在请求中包含一个有效的 CSRF Token。 要将有效的 CSRF Token
作为请求参数指定，请使用 CSRF
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)，如下所示：

::: informalexample

Java

:   ``` java
    mvc
        .perform(post("/").with(csrf()))
    ```

Kotlin

:   ``` kotlin
    mvc.post("/") {
        with(csrf())
    }
    ```
:::

你也可以选择将 CSRF Token 放在请求头中：

::: informalexample

Java

:   ``` java
    mvc
        .perform(post("/").with(csrf().asHeader()))
    ```

Kotlin

:   ``` kotlin
    mvc.post("/") {
        with(csrf().asHeader())
    }
    ```
:::

你还可以通过以下方式测试提供无效的 CSRF Token：

::: informalexample

Java

:   ``` java
    mvc
        .perform(post("/").with(csrf().useInvalidToken()))
    ```

Kotlin

:   ``` kotlin
    mvc.post("/") {
        with(csrf().useInvalidToken())
    }
    ```
:::
