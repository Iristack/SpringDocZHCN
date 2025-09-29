{security-api-url}org/springframework/security/core/userdetails/UserDetails.html\[`UserDetails`\]
由
[`UserDetailsService`](servlet/authentication/passwords/user-details-service.xml#servlet-authentication-userdetailsservice)
返回。
[`DaoAuthenticationProvider`](servlet/authentication/passwords/dao-authentication-provider.xml#servlet-authentication-daoauthenticationprovider)
会验证 `UserDetails`，然后返回一个
[`Authentication`](servlet/authentication/architecture.xml#servlet-authentication-authentication)
对象，该对象的主体（principal）即为配置的 `UserDetailsService` 所返回的
`UserDetails`。
