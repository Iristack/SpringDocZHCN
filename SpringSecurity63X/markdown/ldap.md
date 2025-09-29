LDAP（轻量级目录访问协议）通常被组织用作用户信息的中央存储库以及身份验证服务。
它也可用于存储应用程序用户的权限角色信息。

当 Spring Security 配置为接受
[用户名/密码](servlet/authentication/passwords/index.xml#servlet-authentication-unpwd-input)进行认证时，就会使用基于
LDAP 的认证。 然而，尽管使用用户名和密码进行认证，但它并不使用
`UserDetailsService`，因为在
[绑定认证](#servlet-authentication-ldap-bind) 中，LDAP
服务器不会返回密码，因此应用程序无法对密码进行验证。

LDAP 服务器可以有多种不同的配置方式，因此 Spring Security 的 LDAP
提供程序是完全可配置的。
它使用独立的策略接口来进行认证和角色检索，并提供了默认实现，这些实现可以配置以处理各种情况。

# 必需依赖项 {#servlet-authentication-ldap-required-dependencies}

要开始使用，请将 `spring-security-ldap` 依赖添加到项目中。 使用 Spring
Boot 时，添加以下依赖：

:::: example
::: title
Spring Security LDAP 依赖
:::

Maven

:   ``` xml
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-ldap</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-ldap</artifactId>
    </dependency>
    ```

Gradle

:   ``` groovy
    dependencies {
        implementation "org.springframework.boot:spring-boot-starter-data-ldap"
        implementation "org.springframework.security:spring-security-ldap"
    }
    ```
::::

# 前提条件 {#servlet-authentication-ldap-prerequisites}

在尝试将 LDAP 与 Spring Security 结合使用之前，你应该熟悉 LDAP。
以下链接提供了有关相关概念的良好介绍，并指导如何使用免费的 LDAP 服务器
OpenLDAP 设置目录：https://www.zytrax.com/books/ldap/。 对用于从 Java
访问 LDAP 的 JNDI API 有一定的了解也会有所帮助。 我们的 LDAP
提供程序不使用任何第三方 LDAP 库（如 Mozilla、JLDAP
或其他），但广泛使用了 Spring
LDAP，因此如果你计划添加自定义功能，熟悉该项目可能会很有帮助。

使用 LDAP 身份验证时，应确保正确配置 LDAP 连接池。
如果不熟悉如何操作，请参阅 [Java LDAP
文档](https://docs.oracle.com/javase/jndi/tutorial/ldap/connect/config.html)。

# 设置嵌入式 LDAP 服务器 {#servlet-authentication-ldap-embedded}

首先需要确保有一个 LDAP
服务器可供配置指向。为了简便起见，最好从一个嵌入式 LDAP 服务器开始。
Spring Security 支持使用以下两种之一：

- [嵌入式 UnboundID 服务器](#servlet-authentication-ldap-unboundid)

- [嵌入式 ApacheDS 服务器](#servlet-authentication-ldap-apacheds)

在以下示例中，我们将 `users.ldif` 暴露为类路径资源，以初始化嵌入式 LDAP
服务器，包含两个用户 `user` 和 `admin`，密码均为 `password`：

:::: formalpara
::: title
users.ldif
:::

``` ldif
dn: ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=people,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: people

dn: uid=admin,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: Rod Johnson
sn: Johnson
uid: admin
userPassword: password

dn: uid=user,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: Dianne Emu
sn: Emu
uid: user
userPassword: password

dn: cn=user,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfNames
cn: user
member: uid=admin,ou=people,dc=springframework,dc=org
member: uid=user,ou=people,dc=springframework,dc=org

dn: cn=admin,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfNames
cn: admin
member: uid=admin,ou=people,dc=springframework,dc=org
```
::::

## 嵌入式 UnboundID 服务器 {#servlet-authentication-ldap-unboundid}

如果你想使用
[UnboundID](https://ldap.com/unboundid-ldap-sdk-for-java/)，请指定以下依赖：

:::: example
::: title
UnboundID 依赖
:::

Maven

:   ``` xml
    <dependency>
        <groupId>com.unboundid</groupId>
        <artifactId>unboundid-ldapsdk</artifactId>
        <version>{unboundid-ldapsdk-version}</version>
        <scope>runtime</scope>
    </dependency>
    ```

Gradle

:   ``` groovy
    dependencies {
        runtimeOnly "com.unboundid:unboundid-ldapsdk:{unboundid-ldapsdk-version}"
    }
    ```
::::

然后可以使用 `EmbeddedLdapServerContextSourceFactoryBean` 配置嵌入式
LDAP 服务器： 这将指示 Spring Security 启动一个内存中的 LDAP 服务器：

:::: example
::: title
嵌入式 LDAP 服务器配置
:::

Java

:   ``` java
    @Bean
    public EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
        return EmbeddedLdapServerContextSourceFactoryBean.fromEmbeddedLdapServer();
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun contextSourceFactoryBean(): EmbeddedLdapServerContextSourceFactoryBean {
        return EmbeddedLdapServerContextSourceFactoryBean.fromEmbeddedLdapServer()
    }
    ```
::::

或者，你可以手动配置嵌入式 LDAP 服务器。
如果选择此方法，则需要负责管理嵌入式 LDAP 服务器的生命周期。

:::: example
::: title
显式嵌入式 LDAP 服务器配置
:::

Java

:   ``` java
    @Bean
    UnboundIdContainer ldapContainer() {
        return new UnboundIdContainer("dc=springframework,dc=org",
                    "classpath:users.ldif");
    }
    ```

XML

:   ``` xml
    <b:bean class="org.springframework.security.ldap.server.UnboundIdContainer"
        c:defaultPartitionSuffix="dc=springframework,dc=org"
        c:ldif="classpath:users.ldif"/>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun ldapContainer(): UnboundIdContainer {
        return UnboundIdContainer("dc=springframework,dc=org","classpath:users.ldif")
    }
    ```
::::

## 嵌入式 ApacheDS 服务器 {#servlet-authentication-ldap-apacheds}

:::: note
::: title
:::

Spring Security 使用的是 ApacheDS 1.x 版本，该版本已不再维护。
不幸的是，ApacheDS 2.x 只发布了里程碑版本，尚无稳定版本。 一旦 ApacheDS
2.x 发布稳定版本，我们将考虑升级。
::::

如果你想使用 [Apache
DS](https://directory.apache.org/apacheds/)，请指定以下依赖：

:::: example
::: title
ApacheDS 依赖
:::

Maven

:   ``` xml
    <dependency>
        <groupId>org.apache.directory.server</groupId>
        <artifactId>apacheds-core</artifactId>
        <version>{apacheds-core-version}</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.apache.directory.server</groupId>
        <artifactId>apacheds-server-jndi</artifactId>
        <version>{apacheds-core-version}</version>
        <scope>runtime</scope>
    </dependency>
    ```

Gradle

:   ``` groovy
    dependencies {
        runtimeOnly "org.apache.directory.server:apacheds-core:{apacheds-core-version}"
        runtimeOnly "org.apache.directory.server:apacheds-server-jndi:{apacheds-core-version}"
    }
    ```
::::

然后可以配置嵌入式 LDAP 服务器：

:::: example
::: title
嵌入式 LDAP 服务器配置
:::

Java

:   ``` java
    @Bean
    ApacheDSContainer ldapContainer() {
        return new ApacheDSContainer("dc=springframework,dc=org",
                    "classpath:users.ldif");
    }
    ```

XML

:   ``` xml
    <b:bean class="org.springframework.security.ldap.server.ApacheDSContainer"
        c:defaultPartitionSuffix="dc=springframework,dc=org"
        c:ldif="classpath:users.ldif"/>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun ldapContainer(): ApacheDSContainer {
        return ApacheDSContainer("dc=springframework,dc=org", "classpath:users.ldif")
    }
    ```
::::

# LDAP ContextSource {#servlet-authentication-ldap-contextsource}

当你有了一个可供配置指向的 LDAP 服务器后，需要配置 Spring Security
指向应使用的 LDAP 服务器来认证用户。 为此，创建一个 LDAP
`ContextSource`（相当于 JDBC 的 `DataSource`）。 如果你已经配置了
`EmbeddedLdapServerContextSourceFactoryBean`，Spring Security
将自动创建一个指向嵌入式 LDAP 服务器的 LDAP `ContextSource`。

:::: example
::: title
使用嵌入式 LDAP 服务器的 LDAP 上下文源
:::

Java

:   ``` java
    @Bean
    public EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
        EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean =
                EmbeddedLdapServerContextSourceFactoryBean.fromEmbeddedLdapServer();
        contextSourceFactoryBean.setPort(0);
        return contextSourceFactoryBean;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun contextSourceFactoryBean(): EmbeddedLdapServerContextSourceFactoryBean {
        val contextSourceFactoryBean = EmbeddedLdapServerContextSourceFactoryBean.fromEmbeddedLdapServer()
        contextSourceFactoryBean.setPort(0)
        return contextSourceFactoryBean
    }
    ```
::::

或者，你可以显式地配置 LDAP `ContextSource` 来连接指定的 LDAP 服务器：

:::: example
::: title
LDAP ContextSource
:::

Java

:   ``` java
    ContextSource contextSource(UnboundIdContainer container) {
        return new DefaultSpringSecurityContextSource("ldap://localhost:53389/dc=springframework,dc=org");
    }
    ```

XML

:   ``` xml
    <ldap-server
        url="ldap://localhost:53389/dc=springframework,dc=org" />
    ```

Kotlin

:   ``` kotlin
    fun contextSource(container: UnboundIdContainer): ContextSource {
        return DefaultSpringSecurityContextSource("ldap://localhost:53389/dc=springframework,dc=org")
    }
    ```
::::

# 认证 {#servlet-authentication-ldap-authentication}

Spring Security 的 LDAP 支持不使用
[UserDetailsService](servlet/authentication/passwords/user-details-service.xml#servlet-authentication-userdetailsservice)，因为
LDAP 绑定认证不允许客户端读取密码或其哈希值。 这意味着无法由 Spring
Security 读取并验证密码。

因此，LDAP 支持通过 `LdapAuthenticator` 接口实现。 `LdapAuthenticator`
接口还负责检索所需的任何用户属性。
这是因为属性的权限可能取决于所使用的认证类型。
例如，在以用户身份绑定时，可能需要用用户的自身权限来读取属性。

Spring Security 提供了两个 `LdapAuthenticator` 实现：

- [使用绑定认证](#servlet-authentication-ldap-bind)

- [使用密码认证](#servlet-authentication-ldap-pwd)

# 使用绑定认证 {#servlet-authentication-ldap-bind}

[绑定认证](https://ldap.com/the-ldap-bind-operation/) 是最常用的 LDAP
用户认证机制。 在绑定认证中，用户的凭据（用户名和密码）被提交给 LDAP
服务器进行认证。
使用绑定认证的优点是用户密钥（密码）不需要暴露给客户端，有助于防止泄露。

以下示例展示绑定认证的配置：

:::: example
::: title
绑定认证
:::

Java

:   ``` java
    @Bean
    AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
        LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
        factory.setUserDnPatterns("uid={0},ou=people");
        return factory.createAuthenticationManager();
    }
    ```

XML

:   ``` xml
    <ldap-authentication-provider
        user-dn-pattern="uid={0},ou=people"/>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun authenticationManager(contextSource: BaseLdapPathContextSource): AuthenticationManager {
        val factory = LdapBindAuthenticationManagerFactory(contextSource)
        factory.setUserDnPatterns("uid={0},ou=people")
        return factory.createAuthenticationManager()
    }
    ```
::::

上述简单示例会通过将用户登录名代入提供的模式来获取用户的
DN，并尝试使用登录密码绑定该用户。
如果所有用户都存储在目录的单个节点下，这种方式是可行的。
相反，如果你想配置 LDAP 搜索过滤器来定位用户，可以使用以下方式：

:::: example
::: title
带搜索过滤器的绑定认证
:::

Java

:   ``` java
    @Bean
    AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
        LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
        factory.setUserSearchFilter("(uid={0})");
        factory.setUserSearchBase("ou=people");
        return factory.createAuthenticationManager();
    }
    ```

XML

:   ``` xml
    <ldap-authentication-provider
            user-search-filter="(uid={0})"
        user-search-base="ou=people"/>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun authenticationManager(contextSource: BaseLdapPathContextSource): AuthenticationManager {
        val factory = LdapBindAuthenticationManagerFactory(contextSource)
        factory.setUserSearchFilter("(uid={0})")
        factory.setUserSearchBase("ou=people")
        return factory.createAuthenticationManager()
    }
    ```
::::

如果与前面[所示的 ContextSource
定义](#servlet-authentication-ldap-contextsource)一起使用，这将在 DN
`ou=people,dc=springframework,dc=org` 下执行搜索，使用 `(uid={0})`
作为过滤器。 同样，用户登录名会被替换为过滤器名称中的参数，因此它会查找
`uid` 属性等于用户名的条目。
如果没有提供用户搜索基础，则从根节点开始搜索。

# 使用密码认证 {#servlet-authentication-ldap-pwd}

密码比较是指将用户提供的密码与存储在仓库中的密码进行比对。
这可以通过检索密码属性的值并在本地检查，或者通过执行 LDAP "compare"
操作完成，其中提供的密码被传递到服务器进行比较，而真实密码值永远不会被检索。
当密码使用随机盐正确哈希时，无法执行 LDAP 比较操作。

:::: example
::: title
最小化密码比较配置
:::

Java

:   ``` java
    @Bean
    AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
        LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(
                contextSource, NoOpPasswordEncoder.getInstance());
        factory.setUserDnPatterns("uid={0},ou=people");
        return factory.createAuthenticationManager();
    }
    ```

XML

:   ``` xml
    <ldap-authentication-provider
            user-dn-pattern="uid={0},ou=people">
        <password-compare />
    </ldap-authentication-provider>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun authenticationManager(contextSource: BaseLdapPathContextSource?): AuthenticationManager? {
        val factory = LdapPasswordComparisonAuthenticationManagerFactory(
            contextSource, NoOpPasswordEncoder.getInstance()
        )
        factory.setUserDnPatterns("uid={0},ou=people")
        return factory.createAuthenticationManager()
    }
    ```
::::

以下示例展示了更高级且带有自定义设置的配置：

:::: example
::: title
密码比较配置
:::

Java

:   ``` java
    @Bean
    AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
        LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(
                contextSource, new BCryptPasswordEncoder());
        factory.setUserDnPatterns("uid={0},ou=people");
        factory.setPasswordAttribute("pwd");  
        return factory.createAuthenticationManager();
    }
    ```

XML

:   ``` xml
    <ldap-authentication-provider
            user-dn-pattern="uid={0},ou=people">
        <password-compare password-attribute="pwd"> 
            <password-encoder ref="passwordEncoder" /> 
        </password-compare>
    </ldap-authentication-provider>
    <b:bean id="passwordEncoder"
        class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder" />
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun authenticationManager(contextSource: BaseLdapPathContextSource): AuthenticationManager {
        val factory = LdapPasswordComparisonAuthenticationManagerFactory(
            contextSource, BCryptPasswordEncoder()
        )
        factory.setUserDnPatterns("uid={0},ou=people")
        factory.setPasswordAttribute("pwd") 
        return factory.createAuthenticationManager()
    }
    ```
::::

- 指定密码属性为 `pwd`。

# LdapAuthoritiesPopulator {#_ldapauthoritiespopulator}

Spring Security 的 `LdapAuthoritiesPopulator`
用于确定为用户返回哪些权限。 以下示例展示如何配置
`LdapAuthoritiesPopulator`：

:::: example
::: title
LdapAuthoritiesPopulator 配置
:::

Java

:   ``` java
    @Bean
    LdapAuthoritiesPopulator authorities(BaseLdapPathContextSource contextSource) {
        String groupSearchBase = "";
        DefaultLdapAuthoritiesPopulator authorities =
            new DefaultLdapAuthoritiesPopulator(contextSource, groupSearchBase);
        authorities.setGroupSearchFilter("member={0}");
        return authorities;
    }

    @Bean
    AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource, LdapAuthoritiesPopulator authorities) {
        LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
        factory.setUserDnPatterns("uid={0},ou=people");
        factory.setLdapAuthoritiesPopulator(authorities);
        return factory.createAuthenticationManager();
    }
    ```

XML

:   ``` xml
    <ldap-authentication-provider
        user-dn-pattern="uid={0},ou=people"
        group-search-filter="member={0}"/>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun authorities(contextSource: BaseLdapPathContextSource): LdapAuthoritiesPopulator {
        val groupSearchBase = ""
        val authorities = DefaultLdapAuthoritiesPopulator(contextSource, groupSearchBase)
        authorities.setGroupSearchFilter("member={0}")
        return authorities
    }

    @Bean
    fun authenticationManager(
        contextSource: BaseLdapPathContextSource,
        authorities: LdapAuthoritiesPopulator): AuthenticationManager {
        val factory = LdapBindAuthenticationManagerFactory(contextSource)
        factory.setUserDnPatterns("uid={0},ou=people")
        factory.setLdapAuthoritiesPopulator(authorities)
        return factory.createAuthenticationManager()
    }
    ```
::::

# Active Directory {#_active_directory}

Active Directory
支持其自身的非标准认证选项，且通常的使用模式不太适合标准的
`LdapAuthenticationProvider`。
通常情况下，认证是通过使用域用户名（形式为
`user@domain`）完成的，而不是使用 LDAP 可分辨名称（DN）。
为了简化这一过程，Spring Security 提供了一个专为典型 Active Directory
设置定制的身份验证提供程序。

配置 `ActiveDirectoryLdapAuthenticationProvider` 非常简单。
你只需要提供域名和一个提供服务器地址的 LDAP URL 即可。

:::: note
::: title
:::

也可以通过 DNS 查找获取服务器 IP 地址。
目前尚未支持此功能，但希望在未来的版本中实现。
::::

以下示例配置 Active Directory：

:::: example
::: title
Active Directory 示例配置
:::

Java

:   ``` java
    @Bean
    ActiveDirectoryLdapAuthenticationProvider authenticationProvider() {
        return new ActiveDirectoryLdapAuthenticationProvider("example.com", "ldap://company.example.com/");
    }
    ```

XML

:   ``` xml
    <bean id="authenticationProvider"
            class="org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider">
        <constructor-arg value="example.com" />
        <constructor-arg value="ldap://company.example.com/" />
    </bean>
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun authenticationProvider(): ActiveDirectoryLdapAuthenticationProvider {
        return ActiveDirectoryLdapAuthenticationProvider("example.com", "ldap://company.example.com/")
    }
    ```
::::
