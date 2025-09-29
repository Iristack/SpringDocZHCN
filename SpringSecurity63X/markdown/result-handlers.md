Spring Security 提供了一些 `ResultHandler` 的实现。为了使用 Spring
Security 的 `ResultHandler` 实现，请确保使用以下静态导入：

``` java
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultHandlers.*;
```

# 导出 SecurityContext {#_导出_securitycontext}

很多时候，我们希望查询数据库中的某个仓库（repository），以确认通过
`MockMvc`
发起的请求是否已正确持久化到数据库中。在某些情况下，我们的仓库查询会使用
[Spring Data 集成](features/integrations/data.xml)
功能，基于当前用户的用户名或其他属性来过滤结果。来看一个例子：

仓库接口定义如下：

``` java
private interface MessageRepository extends JpaRepository<Message, Long> {
    @Query("SELECT m.content FROM Message m WHERE m.sentBy = ?#{ principal?.name }")
    List<String> findAllUserMessages();
}
```

测试场景如下：

``` java
mvc
    .perform(post("/message")
        .content("New Message")
        .contentType(MediaType.TEXT_PLAIN)
    )
    .andExpect(status().isOk());

List<String> userMessages = messageRepository.findAllUserMessages();
assertThat(userMessages).hasSize(1);
```

这个测试将无法通过，因为在请求结束后，过滤器链会清空
`SecurityContextHolder`。此时，我们可以将 `TestSecurityContextHolder`
中的内容导出到实际使用的 `SecurityContextHolder` 中，以便继续使用：

``` java
mvc
    .perform(post("/message")
        .content("New Message")
        .contentType(MediaType.TEXT_PLAIN)
    )
    .andDo(exportTestSecurityContext())
    .andExpect(status().isOk());

List<String> userMessages = messageRepository.findAllUserMessages();
assertThat(userMessages).hasSize(1);
```

:::: note
::: title
:::

请记得在各个测试之间清除
`SecurityContextHolder`，否则可能会导致上下文信息在不同测试间泄露。
::::
