本节介绍如何获取 Spring Security 的二进制文件。
有关如何获取源代码的信息，请参阅
[源代码](community.xml#community-source)。

# 版本编号规则 {#_版本编号规则}

Spring Security 的版本格式为 MAJOR.MINOR.PATCH，具体含义如下：

- **主版本（MAJOR）**：可能包含破坏性变更，通常是为了提供更优的安全性以符合现代安全实践。

- **次版本（MINOR）**：包含功能增强，但被视为被动更新（即向后兼容）。

- **补丁版本（PATCH）**：应完全向前和向后兼容，除非是用于修复 Bug
  的更改。

# 使用 Maven {#maven}

与其他大多数开源项目一样，Spring Security 将其依赖项作为 Maven
构件进行发布。本节内容描述了在使用 Maven 时如何引入 Spring Security。

## 在 Spring Boot 中使用 Maven {#getting-maven-boot}

Spring Boot 提供了一个名为 `spring-boot-starter-security`
的启动器，它聚合了与 Spring Security
相关的依赖项。使用该启动器最简单且推荐的方式是通过 IDE 集成（如
[Eclipse](https://joshlong.com/jl/blogPost/tech_tip_geting_started_with_spring_boot.html)、https://www.jetbrains.com/help/idea/spring-boot.html#d1489567e2\[IntelliJ\]
或
[NetBeans](https://github.com/AlexFalappa/nb-springboot/wiki/Quick-Tour)）或访问
<https://start.spring.io> 使用 [Spring
Initializr](https://docs.spring.io/initializr/docs/current/reference/html/)
自动生成项目。

或者，你也可以手动添加该启动器，示例如下：

:::: formalpara
::: title
pom.xml
:::

``` xml
<dependencies>
    <!-- ... 其他依赖项 ... -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
</dependencies>
```
::::

由于 Spring Boot 提供了 Maven BOM
来管理依赖版本，因此你无需显式指定版本号。如果你希望覆盖 Spring Security
的默认版本，可以通过定义一个 Maven 属性来实现：

:::: formalpara
::: title
pom.xml
:::

``` xml
<properties>
    <!-- ... -->
    <spring-security.version>{spring-security-version}</spring-security.version>
</properties>
```
::::

由于 Spring Security
仅在主版本升级时引入破坏性变更，因此你可以安全地将较新版本的 Spring
Security 与 Spring Boot 一起使用。但在某些情况下，你也可能需要同时升级
Spring Framework 的版本。此时可通过添加以下 Maven 属性实现：

:::: formalpara
::: title
pom.xml
:::

``` xml
<properties>
    <!-- ... -->
    <spring.version>{spring-core-version}</spring.version>
</properties>
```
::::

如果你使用了其他功能（例如 LDAP、OAuth 2 等），还需要额外引入相应的
[项目模块和依赖项](modules.xml#modules)。

## 不使用 Spring Boot 的 Maven 配置 {#getting-maven-no-boot}

当你在没有使用 Spring Boot 的项目中引入 Spring Security
时，推荐的做法是使用 Spring Security 自带的
BOM（物料清单），以确保整个项目中使用的 Spring Security
版本一致。示例如下：

:::: formalpara
::: title
pom.xml
:::

``` xml
<dependencyManagement>
    <dependencies>
        <!-- ... 其他依赖项 ... -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-bom</artifactId>
            <version>{spring-security-version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```
::::

一个最小化的 Spring Security Maven 依赖配置通常如下所示：

:::: formalpara
::: title
pom.xml
:::

``` xml
<dependencies>
    <!-- ... 其他依赖项 ... -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-config</artifactId>
    </dependency>
</dependencies>
```
::::

如果你使用了额外的功能（如 LDAP、OAuth 2 等），同样需要引入对应的
[项目模块和依赖项](modules.xml#modules)。

Spring Security 是基于 Spring Framework {spring-core-version}
构建的，但通常可以与任何更新的 Spring Framework 5.x
版本协同工作。许多用户可能会遇到一个问题：Spring Security
的传递依赖会解析出 Spring Framework
{spring-core-version}，这可能导致奇怪的类路径冲突。解决此问题的最简单方法是在
`pom.xml` 的 `<dependencyManagement>` 部分中引入
`spring-framework-bom`：

:::: formalpara
::: title
pom.xml
:::

``` xml
<dependencyManagement>
    <dependencies>
        <!-- ... 其他依赖项 ... -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-framework-bom</artifactId>
            <version>{spring-core-version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```
::::

上述配置可确保 Spring Security
所有传递依赖都使用指定版本（{spring-core-version}）的 Spring 模块。

:::: note
::: title
:::

该方式利用了 Maven 的"物料清单"（BOM）机制，仅适用于 Maven 2.0.9
及以上版本。有关依赖解析机制的更多细节，请参考 [Maven 官方文档 -
依赖机制简介](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html)。
::::

## Maven 仓库 {#maven-repositories}

所有正式发布版本（即以 `.RELEASE` 结尾的版本）均已部署到 Maven Central
仓库，因此你无需在 `pom.xml` 中声明额外的 Maven 仓库。

如果你使用的是 SNAPSHOT 版本，则需要确保已定义 Spring 快照仓库：

:::: formalpara
::: title
pom.xml
:::

``` xml
<repositories>
    <!-- ... 可能存在的其他仓库 ... -->
    <repository>
        <id>spring-snapshot</id>
        <name>Spring Snapshot Repository</name>
        <url>https://repo.spring.io/snapshot</url>
    </repository>
</repositories>
```
::::

如果你使用的是里程碑版（Milestone）或候选发布版（Release
Candidate），则需要定义 Spring Milestone 仓库，示例如下：

:::: formalpara
::: title
pom.xml
:::

``` xml
<repositories>
    <!-- ... 可能存在的其他仓库 ... -->
    <repository>
        <id>spring-milestone</id>
        <name>Spring Milestone Repository</name>
        <url>https://repo.spring.io/milestone</url>
    </repository>
</repositories>
```
::::

# 使用 Gradle {#getting-gradle}

与其他主流开源项目类似，Spring Security 将其依赖发布为 Maven
构件，因此对 Gradle 提供了一流的支持。以下内容描述了在使用 Gradle
时如何引入 Spring Security。

## 在 Spring Boot 中使用 Gradle {#getting-gradle-boot}

Spring Boot 提供了 `spring-boot-starter-security` 启动器，用于聚合
Spring Security 相关的依赖。最简单且推荐的方法是使用 [Spring
Initializr](https://docs.spring.io/initializr/docs/current/reference/html/)，可通过
IDE 插件（如
[Eclipse](https://joshlong.com/jl/blogPost/tech_tip_geting_started_with_spring_boot.html)、https://www.jetbrains.com/help/idea/spring-boot.html#d1489567e2\[IntelliJ\]
或
[NetBeans](https://github.com/AlexFalappa/nb-springboot/wiki/Quick-Tour)）或直接访问
<https://start.spring.io> 创建项目。

你也可以手动添加该启动器：

:::: formalpara
::: title
build.gradle
:::

``` groovy
dependencies {
    implementation "org.springframework.boot:spring-boot-starter-security"
}
```
::::

由于 Spring Boot 使用 Maven BOM
管理依赖版本，因此你无需显式指定版本号。如果想覆盖 Spring Security
的版本，可以通过定义 Gradle 属性实现：

:::: formalpara
::: title
build.gradle
:::

``` groovy
ext['spring-security.version']='{spring-security-version}'
```
::::

由于 Spring Security
仅在主版本更新时引入不兼容变更，因此你可以安全地将较新的 Spring Security
版本与 Spring Boot 配合使用。但有时你可能也需要升级 Spring Framework
的版本，可通过添加以下 Gradle 属性完成：

:::: formalpara
::: title
build.gradle
:::

``` groovy
ext['spring.version']='{spring-core-version}'
```
::::

如果你使用了其他功能（如 LDAP、OAuth 2 等），还需引入相应的
[项目模块和依赖项](modules.xml#modules)。

## 不使用 Spring Boot 的 Gradle 配置 {#_不使用_spring_boot_的_gradle_配置}

当未使用 Spring Boot 时，推荐使用 Spring Security 的 BOM 来保证项目中
Spring Security 版本的一致性。你可以通过使用 [Dependency Management
Plugin](https://github.com/spring-gradle-plugins/dependency-management-plugin)
实现：

:::: formalpara
::: title
build.gradle
:::

``` groovy
plugins {
    id "io.spring.dependency-management" version "1.0.6.RELEASE"
}

dependencyManagement {
    imports {
        mavenBom 'org.springframework.security:spring-security-bom:{spring-security-version}'
    }
}
```
::::

一个最基本的 Spring Security Gradle 依赖配置通常如下所示：

:::: formalpara
::: title
build.gradle
:::

``` groovy
dependencies {
    implementation "org.springframework.security:spring-security-web"
    implementation "org.springframework.security:spring-security-config"
}
```
::::

如果你使用了额外功能（如 LDAP、OAuth 2 等），仍需引入对应的
[项目模块和依赖项](modules.xml#modules)。

Spring Security 基于 Spring Framework {spring-core-version}
构建，通常可兼容任意更高版本的 Spring Framework 5.x。然而，Spring
Security 的传递依赖可能会拉取特定版本的 Spring Framework
{spring-core-version}，从而引发类路径问题。最简单的解决方案是在
`build.gradle` 的 `dependencyManagement` 中引入
`spring-framework-bom`，并配合 Dependency Management Plugin 使用：

:::: formalpara
::: title
build.gradle
:::

``` groovy
plugins {
    id "io.spring.dependency-management" version "1.0.6.RELEASE"
}

dependencyManagement {
    imports {
        mavenBom 'org.springframework:spring-framework-bom:{spring-core-version}'
    }
}
```
::::

上述配置确保了 Spring Security
的所有传递依赖均使用指定版本（{spring-core-version}）的 Spring 模块。

## Gradle 仓库 {#gradle-repositories}

所有正式发布版本（GA 版本，即以 `.RELEASE` 结尾的版本）均已发布至 Maven
Central，因此只需使用 `mavenCentral()` 仓库即可支持这些版本。示例如下：

:::: formalpara
::: title
build.gradle
:::

``` groovy
repositories {
    mavenCentral()
}
```
::::

若使用 SNAPSHOT 版本，则需确保已定义 Spring 快照仓库：

:::: formalpara
::: title
build.gradle
:::

``` groovy
repositories {
    maven { url 'https://repo.spring.io/snapshot' }
}
```
::::

若使用里程碑版或候选发布版，则需定义 Spring Milestone 仓库：

:::: formalpara
::: title
build.gradle
:::

``` groovy
repositories {
    maven { url 'https://repo.spring.io/milestone' }
}
```
::::
