{security-api-url}org/springframework/security/authentication/dao/DaoAuthenticationProvider.html\[`DaoAuthenticationProvider`\]
是一个
[`AuthenticationProvider`](servlet/authentication/architecture.xml#servlet-authentication-authenticationprovider)
的实现，它使用
[`UserDetailsService`](servlet/authentication/passwords/user-details-service.xml#servlet-authentication-userdetailsservice)
和
[`PasswordEncoder`](servlet/authentication/passwords/password-encoder.xml#servlet-authentication-password-storage)
来验证用户名和密码。

本节将介绍 `DaoAuthenticationProvider` 在 Spring Security
中的工作原理。下图说明了在
[读取用户名与密码](servlet/authentication/passwords/index.xml#servlet-authentication-unpwd-input)
章节中提到的
[`AuthenticationManager`](servlet/authentication/architecture.xml#servlet-authentication-authenticationmanager)
的工作流程。

<figure>
<img src="servlet/authentication/unpwd/daoauthenticationprovider.png"
alt="daoauthenticationprovider" />
<figcaption><code>DaoAuthenticationProvider</code> 的使用</figcaption>
</figure>

![number 1]({icondir}/number_1.png) 来自
[读取用户名与密码](servlet/authentication/passwords/index.xml#servlet-authentication-unpwd-input)
章节的身份验证 `Filter` 将一个 `UsernamePasswordAuthenticationToken`
传递给 `AuthenticationManager`，而该管理器由
[`ProviderManager`](servlet/authentication/architecture.xml#servlet-authentication-providermanager)
实现。

![number 2]({icondir}/number_2.png) `ProviderManager` 被配置为使用类型为
`DaoAuthenticationProvider` 的
[AuthenticationProvider](servlet/authentication/architecture.xml#servlet-authentication-authenticationprovider)。

![number 3]({icondir}/number_3.png) `DaoAuthenticationProvider` 通过
`UserDetailsService` 查找 `UserDetails`。

![number 4]({icondir}/number_4.png) `DaoAuthenticationProvider` 使用
[`PasswordEncoder`](servlet/authentication/passwords/password-encoder.xml#servlet-authentication-password-storage)
验证上一步返回的 `UserDetails` 中的密码。

![number 5]({icondir}/number_5.png) 当认证成功时，返回的
[`Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
对象为 `UsernamePasswordAuthenticationToken`
类型，并且其主体（principal）是已配置的 `UserDetailsService` 返回的
`UserDetails`。最终，认证 `Filter` 会将返回的
`UsernamePasswordAuthenticationToken` 设置到
[`SecurityContextHolder`](servlet/authentication/architecture.xml#servlet-authentication-securitycontextholder)
中。
