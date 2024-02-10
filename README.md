## Table of Contents
- JWT Token Validation Library with Spring Security Integration
    * [Scenario](#scenario)
    * [Requirements](#requirements)
    * [Notes](#notes)
- [Implementation](#implementation)    
    * [Structure](#structure)
    * [Testing](#testing)
    * [Linter](#linter)
- [Project setup](#project-setup)

### Scenario

In a distributed system of microservices, thers is a mechanism that attaches a JWT token to each HTTP request. 
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
should be able to use your library with as little security details as possible
4. Optional but recommended: make it work when the signing algorithm is EdDSA

## Implementation
TODO

### Testing  
Tests are located in the ```test``` directory with package definitions matching those of the classes under test. There are two types of tests ```Happy``` and ```Negative``` and are separated in different testing classes.  

### Linter
[Checkstyle](https://checkstyle.org) is configured and used as a linting tool.  
- Configuration is ```config/checkstyle/checkstyle.xml``` based on https://github.com/checkstyle/checkstyle/blob/master/src/main/resources/sun_checks.xml with modified LineLength to 160 instead of 80.  
- Suppressions are ```config/checkstyle/suppressions.xml```  
- ```mvn checkstyle:checkstyle``` runs checkstyle

### Project setup    
1. Clone repository  
    ```
    git clone https://github.com/TaskN/JWTValidator JWTValidator
    ```  
   
