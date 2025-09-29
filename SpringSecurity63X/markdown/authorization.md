以下章节涉及如何适应授权支持方面的变更。

# 方法级安全（Method Security） {#_方法级安全method_security}

## 使用 `-parameters` 编译 {#compile-with-parameters}

Spring Framework 6.1 已移除
`LocalVariableTableParameterNameDiscoverer`（详见
[此问题](https://github.com/spring-projects/spring-framework/issues/29559)）。
这会影响 `@PreAuthorize` 及其他
[方法级安全](servlet/authorization/method-security.xml)
注解处理参数名称的方式。 如果您在方法安全注解中使用了参数名称，例如：

:::: formalpara
::: title
使用 `id` 参数名称的方法安全注解
:::

``` java
@PreAuthorize("@authz.checkPermission(#id, authentication)")
public void doSomething(Long id) {
    // ...
}
```
::::

您必须使用 `-parameters` 编译选项，以确保参数名称在运行时可用。
有关此内容的更多详细信息，请参阅 [升级到 Spring Framework 6.1
页面](https://github.com/spring-projects/spring-framework/wiki/Upgrading-to-Spring-Framework-6.x#core-container)。
