:::: note
::: title
:::

Spring Security 的测试支持需要 spring-test-4.1.3.RELEASE 或更高版本。
::::

要在 Spring MVC 测试中使用 Spring Security，需将 Spring Security 的
`FilterChainProxy` 添加为一个 `Filter`。 此外，还需要添加 Spring
Security 的 `TestSecurityContextHolderPostProcessor`，以支持通过注解在
Spring MVC 测试中
[模拟用户身份运行](servlet/test/mockmvc/setup.xml#test-mockmvc-withmockuser)。
为此，请使用 Spring Security 提供的
`SecurityMockMvcConfigurers.springSecurity()` 方法：

::: informalexample

Java

:   ``` java
    import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;

    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = SecurityConfig.class)
    @WebAppConfiguration
    public class CsrfShowcaseTests {

        @Autowired
        private WebApplicationContext context;

        private MockMvc mvc;

        @BeforeEach
        public void setup() {
            mvc = MockMvcBuilders
                    .webAppContextSetup(context)
                    .apply(springSecurity()) 
                    .build();
        }
        // ...
    }
    ```

Kotlin

:   ``` kotlin
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = [SecurityConfig::class])
    @WebAppConfiguration
    class CsrfShowcaseTests {

        @Autowired
        private lateinit var context: WebApplicationContext

        private var mvc: MockMvc? = null

        @BeforeEach
        fun setup() {
            mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply<DefaultMockMvcBuilder>(springSecurity()) 
                .build()
        }
        // ...
    }
    ```
:::

- `SecurityMockMvcConfigurers.springSecurity()`
  会完成所有必要的初始设置，以将 Spring Security 集成到 Spring MVC
  测试中。
