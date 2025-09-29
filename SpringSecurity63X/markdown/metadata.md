Spring Security 可以 [解析声明方（Asserting
Party）元数据](#parsing-asserting-party-metadata) 以生成
`AssertingPartyDetails` 实例，也可以从 `RelyingPartyRegistration` 实例
[发布依赖方（Relying
Party）元数据](#publishing-relying-party-metadata)。

# 解析 `<saml2:IDPSSODescriptor>` 元数据 {#parsing-asserting-party-metadata}

你可以使用 `RelyingPartyRegistrations` 来解析声明方的元数据，参见
xref:servlet/saml2/login/overview.adoc#servlet-saml2login-relyingpartyregistrationrepository。

当使用 OpenSAML 厂商支持时，生成的 `AssertingPartyDetails` 将是
`OpenSamlAssertingPartyDetails` 类型。
这意味着你可以通过以下方式获取底层的 OpenSAML XMLObject：

::: informalexample

Java

:   ``` java
    OpenSamlAssertingPartyDetails details = (OpenSamlAssertingPartyDetails)
            registration.getAssertingPartyDetails();
    EntityDescriptor openSamlEntityDescriptor = details.getEntityDescriptor();
    ```

Kotlin

:   ``` kotlin
    val details: OpenSamlAssertingPartyDetails =
            registration.getAssertingPartyDetails() as OpenSamlAssertingPartyDetails
    val openSamlEntityDescriptor: EntityDescriptor = details.getEntityDescriptor()
    ```
:::

# 生成 `<saml2:SPSSODescriptor>` 元数据 {#publishing-relying-party-metadata}

你可以使用 `saml2Metadata` DSL 方法来发布一个元数据端点，如下所示：

::: informalexample

Java

:   ``` java
    http
        // ...
        .saml2Login(withDefaults())
        .saml2Metadata(withDefaults());
    ```

Kotlin

:   ``` kotlin
    http {
        //...
        saml2Login { }
        saml2Metadata { }
    }
    ```
:::

你可以使用此元数据端点在你的声明方（如身份提供者
IdP）中注册你的依赖方（服务提供者 SP）。
通常只需要找到正确的表单字段并填入该元数据端点 URL 即可完成注册。

默认情况下，元数据端点为 `/saml2/metadata`，它同时也响应
`/saml2/metadata/{registrationId}` 和
`/saml2/service-provider-metadata/{registrationId}`。

你可以通过 DSL 中的 `metadataUrl` 方法更改此路径：

::: informalexample

Java

:   ``` java
    .saml2Metadata((saml2) -> saml2.metadataUrl("/saml/metadata"))
    ```

Kotlin

:   ``` kotlin
    saml2Metadata {
        metadataUrl = "/saml/metadata"
    }
    ```
:::

# 更改 `RelyingPartyRegistration` 的查找方式 {#_更改_relyingpartyregistration_的查找方式}

如果你有自定义策略来确定应使用哪个
`RelyingPartyRegistration`，可以配置自己的
`Saml2MetadataResponseResolver`，例如下面的例子：

::: informalexample

Java

:   ``` java
    @Bean
    Saml2MetadataResponseResolver metadataResponseResolver(RelyingPartyRegistrationRepository registrations) {
        RequestMatcherMetadataResponseResolver metadata = new RequestMatcherMetadataResponseResolver(
                (id) -> registrations.findByRegistrationId("relying-party"));
        metadata.setMetadataFilename("metadata.xml");
        return metadata;
    }
    ```

Kotlin

:   ``` kotlin
    @Bean
    fun metadataResponseResolver(registrations: RelyingPartyRegistrationRepository): Saml2MetadataResponseResolver {
        val metadata = RequestMatcherMetadataResponseResolver { id: String ->
            registrations.findByRegistrationId("relying-party")
        }
        metadata.setMetadataFilename("metadata.xml")
        return metadata
    }
    ```
:::
