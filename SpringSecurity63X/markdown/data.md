Spring Security 提供了与 Spring Data
的集成，允许在查询中引用当前用户。将用户包含在查询中不仅有用，而且是必要的，尤其是在支持分页结果时，因为如果在查询之后再对结果进行过滤，将无法实现良好的扩展性。

# Spring Data 与 Spring Security 配置 {#data-configuration}

要使用此功能，请添加 `org.springframework.security:spring-security-data`
依赖项，并提供一个类型为 `SecurityEvaluationContextExtension` 的 Bean：

::: informalexample

Java

:   ``` java
    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun securityEvaluationContextExtension(): SecurityEvaluationContextExtension {
        return SecurityEvaluationContextExtension()
    }
    ```
:::

在 XML 配置中，应如下所示：

``` xml
<bean class="org.springframework.security.data.repository.query.SecurityEvaluationContextExtension"/>
```

# 在 \@Query 中使用安全表达式 {#data-query}

现在你可以在查询中使用 Spring Security 表达式：

::: informalexample

Java

:   ``` java
    @Repository
    public interface MessageRepository extends PagingAndSortingRepository<Message,Long> {
        @Query("select m from Message m where m.to.id = ?#{ principal?.id }")
        Page<Message> findInbox(Pageable pageable);
    }
    ```

Kotlin

:   ``` kotlin
    @Repository
    interface MessageRepository : PagingAndSortingRepository<Message,Long> {
        @Query("select m from Message m where m.to.id = ?#{ principal?.id }")
        fun findInbox(pageable: Pageable): Page<Message>
    }
    ```
:::

该查询会检查 `Authentication.getPrincipal().getId()` 是否等于 `Message`
消息接收者的 ID。 请注意，此示例假设你已自定义了 `Principal`
对象，使其成为一个具有 `id` 属性的对象。 通过暴露
`SecurityEvaluationContextExtension` Bean，所有
[常用安全表达式](servlet/authorization/method-security.xml#authorization-expressions)
都可以在查询中使用。
