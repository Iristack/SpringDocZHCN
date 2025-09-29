每种支持的读取用户名和密码的方式都可以使用以下任意一种支持的存储机制：

- 使用
  [内存中认证](servlet/authentication/passwords/in-memory.xml#servlet-authentication-inmemory)
  的简单存储

- 使用 [JDBC
  认证](servlet/authentication/passwords/jdbc.xml#servlet-authentication-jdbc)
  的关系型数据库

- 使用
  [UserDetailsService](servlet/authentication/passwords/user-details-service.xml#servlet-authentication-userdetailsservice)
  的自定义数据存储

- 使用 [LDAP
  认证](servlet/authentication/passwords/ldap.xml#servlet-authentication-ldap)
  的 LDAP 存储
