虽然一直以来都可以使用 HTTP Basic
进行认证，但记住请求头的名称、格式以及对值进行编码总是有些繁琐。
现在可以使用 Spring Security 的 `httpBasic`
[`RequestPostProcessor`](servlet/test/mockmvc/request-post-processors.xml)
来简化这一过程。 例如，下面的代码片段：

::: informalexample

Java

:   ``` java
    mvc
        .perform(get("/").with(httpBasic("user","password")))
    ```

Kotlin

:   ``` kotlin
    mvc.get("/") {
        with(httpBasic("user","password"))
    }
    ```
:::

将尝试使用 HTTP Basic 认证用户名为 \"user\"、密码为 \"password\"
的用户，并确保在 HTTP 请求中包含以下请求头：

``` text
Authorization: Basic dXNlcjpwYXNzd29yZA==
```
