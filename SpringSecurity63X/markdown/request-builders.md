Spring MVC Test 还提供了一个 `RequestBuilder`
接口，可用于创建测试中使用的 `MockHttpServletRequest`。 Spring Security
提供了几个 `RequestBuilder` 实现，可帮助简化测试工作。 要使用 Spring
Security 的 `RequestBuilder` 实现，请确保使用以下静态导入：

::: informalexample

Java

:   ``` java
    import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*;
    ```

Kotlin

:   ``` kotlin
    import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*
    ```
:::
