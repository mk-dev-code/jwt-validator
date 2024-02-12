## Table of Contents
- JWT Token Validation Library with Spring Security Integration
    * [Scenario](#scenario)
    * [Requirements](#requirements)
    * [Notes](#notes)
- [Implementation](#implementation)
    * [Testing](#testing)
    * [Linter](#linter)
- [Installation](#Installation)

### Scenario

In a distributed system of microservices, there is a mechanism that attaches a JWT token to each HTTP request. 
To ensure secure communication between these services, a robust validation system for these tokens is needed.
The task is to create a library that enables microservices to:
1. Validate these JWT tokens,
2. Integrate seamlessly with Spring Security
3. Extract essential user identification details from the tokens.

### Requirements

Develop a library that validates JWT tokens using a public key obtained from a JWKS
(JSON Web Key Set), integrates with Spring Security to block requests with invalid
tokens, and extracts the "sub" claim from the token. The sub claim should then be
readily available for clients of your library, as it contains user id. Include a README
explaining how to enable and configure the library

### Notes

1. The token is stored in x-secret-token header
2. The token is a standard base64 encoded signed JWT
3. The library is intended for clients with limited knowledge of web security, so they
should be able to use the library with as little security details as possible
4. Optional but recommended: make it work when the signing algorithm is EdDSA

## Implementation

JWT Token Validation Library, `jwt-validator`, is designed to simplify the process of validating JSON Web Tokens (JWT) in Java applications. It leverages the [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) library, providing a convenient interface for handling JWT validation.

The initialization of `jwt-validator` is straightforward, requiring only the key server URL. If utilized in a Spring Boot environment, an HTTP header carrying the JWT is also required.

[Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) is highly customizable. New values can be set via Java system properties. For example, if the default HTTP connect timeout needs to be changed, you can set it like this:
```bash
-Dcom.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout=3000
```
The full list is [here](https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/constant-values.html)

Token validation is performed by the JwtValidationService class, and it is designed to be thread-safe.

JwtValidationFilter is a OncePerRequestFilter and can be leveraged directly in Spring Boot HttpSecurity. In this case, on successful authentication, the filter sets authentication to JwtValidationToken, and the JWT subject is accessible via `getName()` and claims are accessible via `getDetails()` methods.

If and expiration is set in JWT then it is checked during validation process.

There is a sample Spring Boot project in the example folder.


### Testing  
Tests are located in the ```test``` directory with package definitions matching those of the classes under test.

### Linter
[Checkstyle](https://checkstyle.org) is configured and used as a linting tool.  
- Configuration is ```config/checkstyle/checkstyle.xml``` based on https://github.com/checkstyle/checkstyle/blob/master/src/main/resources/sun_checks.xml with modified LineLength to 160 instead of 80.  
- Suppressions are ```config/checkstyle/suppressions.xml```  
- ```mvn checkstyle:checkstyle``` runs checkstyle

## Installation    
1. Clone repository  
    `git clone https://github.com/mk-dev-code/jwt-validator jwt-validator`
2. Build	
	`mvn clean install`
3. Add dependecy 
```xml						
		<dependency>
		    <groupId>corp.mkdev</groupId>
		    <artifactId>jwt-validator</artifactId>
		    <version>1.0.0</version>
		</dependency>
```
## Integration
1. In Spring Boot:  
   1.1. Enable web security by annotating a class with `@EnableWebSecurity`.  
   1.2. Create a `JwtValidationFilter`. If autowired, ensure that a bean providing `JwtValidationFilter` is available elsewhere. Alternatively, allow component scanning using `@ComponentScan(basePackages = {"corp.mkdev.jwt.validator"})` to make `JwtValidationFilterConfig` visible. 

```java
    @Autowired
    private JwtValidationFilter jwtValidationFilter
```

JwtValidationFilterConfig expects `jwt.validation.jks.url`, `jwt.validation.header` and `jwt.validation.algs`. Ensure these are set in `application. properties` file

```properties
#Key server url
jwt.validation.jks.url=http://127.0.0.1:8080/jwks.json

#Http header carrying token
jwt.validation.header=x-secret-token

#Signing algorithms
jwt.validation.algs=EdDSA,RS256
```
  
1.3. Create a filter chain and add JwtValidationFilter before UsernamePasswordAuthenticationFilter.  
```java
    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                                    (authorize) -> authorize
                                    .requestMatchers("/auth/**").authenticated()                                    
                                    .anyRequest().permitAll()
                                    )
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(jwtValidationFilter,UsernamePasswordAuthenticationFilter.class)        
        ;
        return http.build();
    }
```
1.4. On successfull token verification Authentication is set to JwtValidationToken, and the JWT subject is accessible via `getName()` and claims are accessible via `getDetails()` methods.
```java
    @GetMapping(path = { "/auth/ping" })
    public String authPing(Authentication authentication) {
        return "Subject:("+authentication.getName()+") Claims:" + authentication.getDetails();
    }
```





