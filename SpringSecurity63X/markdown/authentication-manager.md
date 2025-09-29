该元素会创建 Spring Security 的 `ProviderManager`
类的实例，而这个实例需要配置一个或多个 `AuthenticationProvider`
实例的列表。 这些 `AuthenticationProvider`
可以通过命名空间提供的语法元素创建，也可以是标准的 Bean 定义，并通过
`authentication-provider` 元素标记添加到列表中。

# \<authentication-manager\> {#nsa-authentication-manager}

每个使用命名空间的 Spring Security 应用都必须包含此元素。
它负责注册提供认证服务的 `AuthenticationManager`。 所有用于创建
`AuthenticationProvider` 实例的元素都应该是该元素的子元素。

## \<authentication-manager\> 属性 {#nsa-authentication-manager-attributes}

- **alias** 此属性允许你为内部实例定义一个别名，以便在自己的配置中使用。

<!-- -->

- **erase-credentials** 如果设置为
  `true`，则在用户完成认证后，`AuthenticationManager` 将尝试清除返回的
  `Authentication` 对象中的任何凭据数据。 实际上，这对应于
  [`ProviderManager`](servlet/authentication/architecture.xml#servlet-authentication-providermanager)
  的 `eraseCredentialsAfterAuthentication` 属性。

<!-- -->

- **observation-registry-ref** 对 `ObservationRegistry` 的引用，供
  `FilterChain` 和相关组件使用。

<!-- -->

- **id** 此属性允许你为内部实例定义一个 ID，以便在自己的配置中使用。
  其功能与 `alias` 相同，但与其他使用 `id` 属性的元素保持一致。

## \<authentication-manager\> 的子元素 {#nsa-authentication-manager-children}

- [authentication-provider](#nsa-authentication-provider)

- [ldap-authentication-provider](servlet/appendix/namespace/ldap.xml#nsa-ldap-authentication-provider)

# \<authentication-provider\> {#nsa-authentication-provider}

除非带有 `ref` 属性，否则该元素是配置 `DaoAuthenticationProvider`
的简写形式。 `DaoAuthenticationProvider` 从 `UserDetailsService`
加载用户信息，并将登录时提供的用户名和密码组合与存储值进行比较。
`UserDetailsService` 实例可以通过可用的命名空间元素（如
`jdbc-user-service`）定义，或者通过 `user-service-ref`
属性指向应用程序上下文中其他地方定义的 Bean。

## \<authentication-provider\> 的父元素 {#nsa-authentication-provider-parents}

- [authentication-manager](#nsa-authentication-manager)

## \<authentication-provider\> 属性 {#nsa-authentication-provider-attributes}

- **ref** 定义一个对实现了 `AuthenticationProvider` 接口的 Spring Bean
  的引用。

如果你编写了自己的 `AuthenticationProvider` 实现（或出于某种原因希望将
Spring Security 提供的某个实现作为传统 Bean
配置），可以使用以下语法将其添加到 `ProviderManager` 的内部列表中：

``` xml
<security:authentication-manager>
  <security:authentication-provider ref="myAuthenticationProvider" />
</security:authentication-manager>
<bean id="myAuthenticationProvider" class="com.something.MyAuthenticationProvider"/>
```

- **user-service-ref** 对实现了 `UserDetailsService` 接口的 Bean
  的引用，该 Bean 可通过标准 Bean 元素或自定义的 `user-service`
  元素创建。

## \<authentication-provider\> 的子元素 {#nsa-authentication-provider-children}

- [jdbc-user-service](#nsa-jdbc-user-service)

- [ldap-user-service](servlet/appendix/namespace/ldap.xml#nsa-ldap-user-service)

- [password-encoder](#nsa-password-encoder)

- [user-service](#nsa-user-service)

# \<jdbc-user-service\> {#nsa-jdbc-user-service}

用于创建基于 JDBC 的 `UserDetailsService`。

## \<jdbc-user-service\> 属性 {#nsa-jdbc-user-service-attributes}

- **authorities-by-username-query**
  用于根据用户名查询用户所授予权限（authorities）的 SQL 语句。

默认值为：

    select username, authority from authorities where username = ?

- **cache-ref** 定义一个用于 `UserDetailsService` 的缓存引用。

<!-- -->

- **data-source-ref** 提供所需数据库表的 `DataSource` Bean 的 ID。

<!-- -->

- **group-authorities-by-username-query**
  用于根据用户名查询用户所属组权限的 SQL 语句。 默认值为：

<!-- -->

    select
    g.id, g.group_name, ga.authority
    from
    groups g, group_members gm, group_authorities ga
    where
    gm.username = ? and g.id = ga.group_id and g.id = gm.group_id

- **id** Bean 标识符，用于在上下文其他位置引用该 Bean。

<!-- -->

- **role-prefix**
  一个非空字符串前缀，将被添加到从持久化存储加载的角色字符串上（默认为
  \"ROLE\_\"）。 若不需要前缀（且默认值非空），可设为 \"none\"。

<!-- -->

- **users-by-username-query** 用于根据用户名查询用户名、密码和启用状态的
  SQL 语句。 默认值为：

<!-- -->

    select username, password, enabled from users where username = ?

# \<password-encoder\> {#nsa-password-encoder}

认证提供者（Authentication
Provider）可选择性地配置密码编码器，具体说明见
[密码存储](features/authentication/password-storage.xml#authentication-password-storage)。
配置后，相应的 `PasswordEncoder` 实例会被注入到 Bean 中。

## \<password-encoder\> 的父元素 {#nsa-password-encoder-parents}

- [authentication-provider](#nsa-authentication-provider)

- [password-compare](servlet/appendix/namespace/authentication-manager.xml#nsa-password-compare)

## \<password-encoder\> 属性 {#nsa-password-encoder-attributes}

- **hash** 定义用于用户密码的哈希算法。 我们强烈建议不要使用
  MD4，因为它是一种非常弱的哈希算法。

<!-- -->

- **ref** 定义一个对实现了 `PasswordEncoder` 接口的 Spring Bean 的引用。

# \<user-service\> {#nsa-user-service}

从属性文件或一组 \"user\" 子元素创建一个内存中的 `UserDetailsService`。
用户名会在内部转换为小写，以支持不区分大小写的查找。因此，如果需要区分大小写，则不应使用此方式。

## \<user-service\> 属性 {#nsa-user-service-attributes}

- **id** Bean 标识符，用于在上下文中其他位置引用该 Bean。

<!-- -->

- **properties** 属性文件的位置，每行格式如下：

<!-- -->

    username=password,grantedAuthority[,grantedAuthority][,enabled|disabled]

## \<user-service\> 的子元素 {#nsa-user-service-children}

- [user](#nsa-user)

# \<user\> {#nsa-user}

表示应用中的一个用户。

## \<user\> 的父元素 {#nsa-user-parents}

- [user-service](#nsa-user-service)

## \<user\> 属性 {#nsa-user-attributes}

- **authorities** 授予该用户的一个或多个权限（authority）。
  权限之间用逗号分隔（不要加空格）。例如：\"ROLE_USER,ROLE_ADMINISTRATOR\"

<!-- -->

- **disabled** 可设置为 \"true\"，将账户标记为禁用且不可用。

<!-- -->

- **locked** 可设置为 \"true\"，将账户标记为锁定且不可用。

<!-- -->

- **name** 分配给该用户的用户名。

<!-- -->

- **password** 分配给该用户的密码。
  如果对应的认证提供者支持哈希处理，密码可以是已哈希的（记得设置
  `user-service` 元素的 \"hash\" 属性）。
  当数据仅用于获取权限而不用于认证时，此属性可以省略。
  如果省略，命名空间会生成一个随机值，防止其被意外用于认证。
  该属性不能为空。
