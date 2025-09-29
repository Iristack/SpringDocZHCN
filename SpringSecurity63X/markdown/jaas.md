Spring Security 提供了一个包，用于将认证请求委托给 Java
认证与授权服务（Java Authentication and Authorization Service,
JAAS）。本节将讨论该包的内容。

# AbstractJaasAuthenticationProvider {#jaas-abstractjaasauthenticationprovider}

`AbstractJaasAuthenticationProvider` 类是 Spring Security 所提供的 JAAS
`AuthenticationProvider` 实现的基础类。子类必须实现一个用于创建
`LoginContext` 的方法。`AbstractJaasAuthenticationProvider`
包含多个可以注入的依赖项，这些内容将在本节后续部分中进行说明。

## JAAS CallbackHandler

大多数 JAAS `LoginModule`
实例都需要某种形式的回调（callback）。这些回调通常用于从用户获取用户名和密码。

在 Spring Security 的部署中，用户交互由 Spring Security
负责（通过其认证机制）。因此，当认证请求被委托给 JAAS 时，Spring
Security 的认证机制已经完全填充了一个包含 JAAS `LoginModule`
所需全部信息的 `Authentication` 对象。

为此，Spring Security 的 JAAS
包提供了两个默认的回调处理器：`JaasNameCallbackHandler` 和
`JaasPasswordCallbackHandler`。这两个处理器都实现了
`JaasAuthenticationCallbackHandler`
接口。在大多数情况下，开发者可以直接使用这些回调处理器，而无需深入了解其内部工作机制。

对于需要完全控制回调行为的场景，`AbstractJaasAuthenticationProvider`
在内部会将这些 `JaasAuthenticationCallbackHandler` 实例包装为
`InternalCallbackHandler`。`InternalCallbackHandler` 是实际实现标准 JAAS
`CallbackHandler` 接口的类。每当使用 JAAS `LoginModule`
时，它会被传入一组已配置的 `InternalCallbackHandler` 实例列表。如果
`LoginModule` 向这些 `InternalCallbackHandler`
发起回调请求，则该请求会进一步传递给被包装的
`JaasAuthenticationCallbackHandler` 实例进行处理。

## JAAS AuthorityGranter

JAAS 基于"主体"（principals）工作，即使是 "roles"（角色）在 JAAS
中也是以 principal 的形式表示。而 Spring Security 则基于
`Authentication` 对象工作，每个 `Authentication` 对象包含一个 principal
和多个 `GrantedAuthority` 实例。

为了便于在这两种不同概念之间建立映射关系，Spring Security 的 JAAS
模块提供了一个 `AuthorityGranter` 接口。

`AuthorityGranter` 的职责是检查一个 JAAS principal，并返回一组代表该
principal
所拥有权限的字符串。对于每一个返回的权限字符串，`AbstractJaasAuthenticationProvider`
都会创建一个 `JaasGrantedAuthority`（实现了 Spring Security 的
`GrantedAuthority` 接口），其中包含该权限字符串以及最初传递给
`AuthorityGranter` 的 JAAS principal。

`AbstractJaasAuthenticationProvider` 会在使用 JAAS `LoginModule`
成功验证用户凭据后，访问返回的 `LoginContext` 来获取 JAAS
principals。具体来说，会调用 `LoginContext.getSubject().getPrincipals()`
方法，然后将得到的每一个 principal 依次传递给通过
`setAuthorityGranters(List)` 属性配置在
`AbstractJaasAuthenticationProvider` 上的所有 `AuthorityGranter` 实例。

由于每个 JAAS principal 的含义都与具体实现相关，Spring Security
并未提供可用于生产的 `AuthorityGranter`
实现。不过，在单元测试中提供了一个 `TestAuthorityGranter`
示例，展示了如何实现一个简单的 `AuthorityGranter`。

# DefaultJaasAuthenticationProvider {#jaas-defaultjaasauthenticationprovider}

`DefaultJaasAuthenticationProvider` 允许将一个 JAAS `Configuration`
对象作为依赖项注入。然后它使用这个注入的 `Configuration` 创建
`LoginContext`。这意味着 `DefaultJaasAuthenticationProvider`
不绑定于任何特定的 `Configuration` 实现，这与
`JaasAuthenticationProvider` 不同。

## InMemoryConfiguration {#jaas-inmemoryconfiguration}

为了方便向 `DefaultJaasAuthenticationProvider` 注入
`Configuration`，Spring Security 提供了一个名为 `InMemoryConfiguration`
的内存实现。

该类的构造函数接受一个 `Map`
参数，其中每个键代表一个登录配置名称，值则是一个 `AppConfigurationEntry`
实例数组。`InMemoryConfiguration` 还支持设置一个默认的
`AppConfigurationEntry` 数组，当提供的 `Map`
中找不到对应键时，将使用该默认数组。更多细节请参见
{security-api-url}org/springframework/security/authentication/jaas/memory/InMemoryConfiguration.html\[`InMemoryConfiguration`
的 Javadoc\]。

## DefaultJaasAuthenticationProvider 示例配置 {#jaas-djap-config}

虽然使用 Spring 配置 `InMemoryConfiguration` 可能比标准 JAAS
配置文件更冗长，但将其与 `DefaultJaasAuthenticationProvider`
结合使用更加灵活，因为它不依赖于默认的 `Configuration` 实现。

以下示例展示了如何配置使用 `InMemoryConfiguration` 的
`DefaultJaasAuthenticationProvider`。注意，你也可以轻松地将自定义的
`Configuration` 实现注入到 `DefaultJaasAuthenticationProvider` 中。

``` xml
<bean id="jaasAuthProvider"
class="org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider">
<property name="configuration">
<bean class="org.springframework.security.authentication.jaas.memory.InMemoryConfiguration">
<constructor-arg>
    <map>
    <!--
    SPRINGSECURITY 是 AbstractJaasAuthenticationProvider 的默认 loginContextName
    -->
    <entry key="SPRINGSECURITY">
    <array>
    <bean class="javax.security.auth.login.AppConfigurationEntry">
        <constructor-arg value="sample.SampleLoginModule" />
        <constructor-arg>
        <util:constant static-field=
            "javax.security.auth.login.AppConfigurationEntry$LoginModuleControlFlag.REQUIRED"/>
        </constructor-arg>
        <constructor-arg>
        <map></map>
        </constructor-arg>
        </bean>
    </array>
    </entry>
    </map>
    </constructor-arg>
</bean>
</property>
<property name="authorityGranters">
<list>
    <!-- 你需要编写自己的 AuthorityGranter 实现 -->
    <bean class="org.springframework.security.authentication.jaas.TestAuthorityGranter"/>
</list>
</property>
</bean>
```

# JaasAuthenticationProvider {#jaas-jaasauthenticationprovider}

`JaasAuthenticationProvider` 假设默认的 `Configuration` 是
[`ConfigFile`](https://docs.oracle.com/javase/8/docs/jre/api/security/jaas/spec/com/sun/security/auth/login/ConfigFile.html)
类的一个实例。做出此假设是为了尝试更新
`Configuration`。然后，`JaasAuthenticationProvider` 使用默认的
`Configuration` 来创建 `LoginContext`。

假设我们有一个 JAAS 登录配置文件 `/WEB-INF/login.conf`，其内容如下：

``` txt
JAASTest {
    sample.SampleLoginModule required;
};
```

像所有 Spring Security Bean 一样，`JaasAuthenticationProvider`
通过应用上下文进行配置。以下定义对应于上述 JAAS 登录配置文件：

``` xml
<bean id="jaasAuthenticationProvider"
class="org.springframework.security.authentication.jaas.JaasAuthenticationProvider">
<property name="loginConfig" value="/WEB-INF/login.conf"/>
<property name="loginContextName" value="JAASTest"/>
<property name="callbackHandlers">
<list>
<bean
    class="org.springframework.security.authentication.jaas.JaasNameCallbackHandler"/>
<bean
    class="org.springframework.security.authentication.jaas.JaasPasswordCallbackHandler"/>
</list>
</property>
<property name="authorityGranters">
    <list>
    <bean class="org.springframework.security.authentication.jaas.TestAuthorityGranter"/>
    </list>
</property>
</bean>
```

# 以 Subject 身份运行 {#jaas-apiprovision}

如果启用了相关配置，`JaasApiIntegrationFilter` 会尝试以
`JaasAuthenticationToken` 中的 `Subject`
身份执行操作。这意味着你可以通过以下方式访问当前的 `Subject`：

``` java
Subject subject = Subject.getSubject(AccessController.getContext());
```

你可以通过
[jaas-api-provision](servlet/appendix/namespace/http.xml#nsa-http-jaas-api-provision)
属性来启用此项集成功能。此特性在与依赖 JAAS Subject
已经被正确填充的旧系统或外部 API 集成时非常有用。
