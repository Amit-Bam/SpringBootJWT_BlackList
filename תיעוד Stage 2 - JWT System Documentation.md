# תיעוד Stage 2 - JWT System Documentation

<div dir="rtl">

## השוואה בין Stage 1 ל-Stage 2

### מה היה ב-Stage 1:
- JWT Token Generation בלבד
- אין JWT Authentication Filter
- אין Token Validation
- endpoints לא מוגנים בפועל
- אין Authorization headers processing

### מה נוסף ב-Stage 2:
- **JwtAuthenticationFilter** - מעבד tokens בכל בקשה
- **Token Validation** - בודק תקינות ותפוגה של tokens
- **Protected Endpoints** - endpoints מוגנים באמת
- **Authorization Header Processing** - קריאת Bearer tokens (נושא) 
- **Role-based Access Control** - הגבלות על בסיס תפקידים
- **SecurityContext Management** - ניהול אימות ברמת הבקשה

## תרשים ארכיטקטורת המערכת - System Architecture

</div>

```mermaid
graph TB
    Client[Client Application<br/>]
    
    subgraph SpringBoot["Spring Boot Application - Stage 2"]
        direction TB
        AuthController[AuthenticationController<br/>POST /api/login]
        UserController[UserController<br/>GET /api/protected-message]
        AuthService[AuthenticationService]
        UserService[CustomUserDetailsService]
        JwtUtil[JwtUtil<br/>Token Generation & Validation]
        JwtFilter[JwtAuthenticationFilter<br/>Token Processing]
        Security[SecurityConfig<br/>Security & Filter Chain]
        
        subgraph Database["Database Layer"]
            UserRepo[UserRepository]
            RoleRepo[RoleRepository]
            UserEntity[User Entity]
            RoleEntity[Role Entity]
        end
        
        subgraph DTOs["Data Transfer Objects"]
            AuthRequest[AuthenticationRequest]
            AuthResponse[AuthenticationResponse]
            UserDto[UserDto]
            RoleDto[RoleDto]
        end
    end
    
    MySQL[(MySQL Database<br/>)]
    
    Client -->|HTTP POST /api/login| JwtFilter
    Client -->|HTTP GET /api/protected-message + Bearer Token| JwtFilter
    
    JwtFilter -->|Process & Validate Token| JwtUtil
    JwtFilter -->|Load User Details| UserService
    JwtFilter -->|Forward if Valid| AuthController
    JwtFilter -->|Forward if Valid| UserController
    
    AuthController --> AuthService
    AuthService --> UserService
    AuthService --> JwtUtil
    UserService --> UserRepo
    UserRepo --> UserEntity
    UserEntity --> RoleEntity
    RoleEntity --> RoleRepo
    
    UserRepo --> MySQL
    RoleRepo --> MySQL
    
    AuthController --> DTOs
    UserController --> DTOs
```

<div dir="rtl">

## תרשים זרימת Authentication מלאה - Complete Authentication Flow

</div>

```mermaid
sequenceDiagram
    participant Client
    participant JwtFilter as JwtAuthenticationFilter
    participant AuthController as AuthenticationController
    participant AuthService as AuthenticationService
    participant UserService as CustomUserDetailsService
    participant JwtUtil
    participant UserRepo as UserRepository
    participant DB as MySQL Database
    
    Note over Client, DB: Login Process
    Client->>JwtFilter: POST /api/login {username, password}
    JwtFilter->>AuthController: Forward (no token needed for login)
    AuthController->>AuthService: authenticate(authRequest)
    AuthService->>UserService: loadUserByUsername(username)
    UserService->>UserRepo: findByUsername(username)
    UserRepo->>DB: SELECT user with roles
    DB-->>UserRepo: User entity + roles
    UserRepo-->>UserService: User with roles
    UserService-->>AuthService: UserDetails object
    AuthService->>AuthService: validatePassword(password)
    
    alt Password Valid
        AuthService->>JwtUtil: generateToken(authRequest, userDetails)
        JwtUtil->>JwtUtil: Create JWT with claims & signature
        JwtUtil-->>AuthService: JWT token string
        AuthService-->>AuthController: AuthenticationResponse(token)
        AuthController-->>JwtFilter: 200 OK {accessToken}
        JwtFilter-->>Client: 200 OK {accessToken}
    else Password Invalid
        AuthService-->>AuthController: AuthenticationServiceException
        AuthController-->>JwtFilter: 401 Unauthorized
        JwtFilter-->>Client: 401 Unauthorized
    end
    
    Note over Client, DB: Protected Request Process
    Client->>JwtFilter: GET /api/protected-message<br/>Authorization: Bearer <token>
    JwtFilter->>JwtFilter: Extract token from Authorization header
    JwtFilter->>JwtUtil: extractUsername(token)
    JwtUtil-->>JwtFilter: username
    JwtFilter->>UserService: loadUserByUsername(username)
    UserService->>UserRepo: findByUsername(username)
    UserRepo-->>UserService: UserDetails
    UserService-->>JwtFilter: UserDetails
    JwtFilter->>JwtUtil: validateToken(token, userDetails)
    JwtUtil->>JwtUtil: Check signature & expiration
    
    alt Token Valid
        JwtUtil-->>JwtFilter: true
        JwtFilter->>JwtFilter: Set SecurityContext Authentication
        JwtFilter->>UserController: Forward request
        UserController-->>JwtFilter: Protected content
        JwtFilter-->>Client: 200 OK with content
    else Token Invalid
        JwtUtil-->>JwtFilter: false/exception
        JwtFilter-->>Client: 401 Unauthorized
    end
```

<div dir="rtl">

## תרשים JWT Filter Processing - JWT Filter Flow

</div>

```mermaid
flowchart TD
    Start([HTTP Request])
    Filter[JwtAuthenticationFilter.doFilterInternal]
    CheckHeader{Authorization Header<br/>exists and starts with<br/>Bearer?}
    ExtractToken[Extract token from<br/>Authorization: Bearer TOKEN]
    CheckQuery{Token in<br/>query parameter?}
    ExtractQuery[Extract token from<br/>?token=TOKEN]
    NoToken[No token found]
    ExtractUsername[JwtUtil.extractUsername]
    LoadUser[CustomUserDetailsService.<br/>loadUserByUsername]
    ValidateToken[JwtUtil.validateToken]
    SetAuth[Create UsernamePasswordAuthenticationToken<br/>Set SecurityContext]
    Forward[Continue filter chain]
    Error401[Return 401 Unauthorized]
    Error500[Return 500 Internal Server Error]
    
    Start --> Filter
    Filter --> CheckHeader
    CheckHeader -->|Yes| ExtractToken
    CheckHeader -->|No| CheckQuery
    CheckQuery -->|Yes| ExtractQuery
    CheckQuery -->|No| NoToken
    ExtractToken --> ExtractUsername
    ExtractQuery --> ExtractUsername
    NoToken --> Forward
    
    ExtractUsername --> LoadUser
    LoadUser --> ValidateToken
    ValidateToken -->|Valid| SetAuth
    ValidateToken -->|Invalid| Error401
    SetAuth --> Forward
    
    ExtractUsername -->|Exception| Error401
    LoadUser -->|UserNotFoundException| Error401
    LoadUser -->|Other Exception| Error500
```

<div dir="rtl">

## תרשים יחסי ישויות - Entity Relationship Diagram

</div>

```mermaid
erDiagram
    USER {
        Long id PK
        String username UK
        String password
    }
    
    ROLE {
        Long id PK
        String roleName UK
    }
    
    USERS_ROLES {
        Long user_id FK
        Long role_id FK
    }
    
    USER ||--o{ USERS_ROLES : "has roles"
    ROLE ||--o{ USERS_ROLES : "assigned to users"
```

<div dir="rtl">

## תרשים מחלקות - Class Diagram

</div>

```mermaid
classDiagram
    class AuthenticationController {
        -AuthenticationService authenticationService
        +authenticateUser(AuthenticationRequest) ResponseEntity
    }
    
    class UserController {
        +home() String
    }
    
    class AuthenticationService {
        -CustomUserDetailsService userDetailsService
        -JwtUtil jwtUtil
        -PasswordEncoder passwordEncoder
        +authenticate(AuthenticationRequest) AuthenticationResponse
    }
    
    class CustomUserDetailsService {
        -UserRepository userRepository
        +loadUserByUsername(String) UserDetails
        -mapRolesToAuthorities(List~Role~) Collection~GrantedAuthority~
    }
    
    class JwtUtil {
        -Key key
        +generateToken(AuthenticationRequest, UserDetails) String
        +validateToken(String, UserDetails) boolean
        +extractUsername(String) String
        +extractExpiration(String) Date
        -extractClaim(String, Function) T
        -extractAllClaims(String) Claims
        -isTokenExpired(String) Boolean
        -getKey() Key
    }
    
    class JwtAuthenticationFilter {
        -JwtUtil jwtUtil
        -CustomUserDetailsService userDetailsService
        +doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain) void
    }
    
    class SecurityConfig {
        -JwtUtil jwtUtil
        -CustomUserDetailsService userDetailsService
        +passwordEncoder() PasswordEncoder
        +filterChain(HttpSecurity) SecurityFilterChain
    }
    
    class User {
        -Long id
        -String username
        -String password
        -List~Role~ roles
    }
    
    class Role {
        -Long id
        -String roleName
        -List~User~ users
    }
    
    class AuthenticationRequest {
        -String username
        -String password
    }
    
    class AuthenticationResponse {
        -String accessToken
    }
    
    class UserDto {
        -Long id
        -String username
        -String password
        -Set~String~ roles
    }
    
    class RoleDto {
        -Long id
        -String roleName
    }
    
    class JwtProperties {
        +EXPIRATION_TIME int
        +TOKEN_PREFIX String
        +HEADER_STRING String
    }
    
    class UserRepository {
        +findByUsername(String) User
        +findUserByUsername(String) User
    }
    
    class RoleRepository {
        +findRolesByUserId(Long) List~Role~
        +findByRoleName(String) Optional~Role~
    }
    
    AuthenticationController --> AuthenticationService
    AuthenticationController --> AuthenticationRequest
    AuthenticationController --> AuthenticationResponse
    
    UserController --> String
    
    AuthenticationService --> CustomUserDetailsService
    AuthenticationService --> JwtUtil
    AuthenticationService --> AuthenticationRequest
    AuthenticationService --> AuthenticationResponse
    
    CustomUserDetailsService --> UserRepository
    CustomUserDetailsService --> User
    CustomUserDetailsService --> Role
    
    JwtUtil --> AuthenticationRequest
    JwtUtil --> JwtProperties
    
    JwtAuthenticationFilter --> JwtUtil
    JwtAuthenticationFilter --> CustomUserDetailsService
    JwtAuthenticationFilter --> JwtProperties
    
    SecurityConfig --> JwtUtil
    SecurityConfig --> CustomUserDetailsService
    SecurityConfig --> JwtAuthenticationFilter
    
    UserRepository --> User
    RoleRepository --> Role
    User --> Role
    
    UserDto --> String
    RoleDto --> String
```

<div dir="rtl">

## זרימת עיבוד JWT - JWT Processing Flow

</div>

```mermaid
graph TD
    TokenGen[JWT Token Generation]
    TokenUse[JWT Token Usage]
    TokenVal[JWT Token Validation]
    
    subgraph Generation["Token Generation Process"]
        Login[User Login]
        ValidateCreds[Validate Credentials]
        CreateClaims[Create JWT Claims]
        SignToken[Sign Token with Secret Key]
        ReturnToken[Return JWT to Client]
        
        Login --> ValidateCreds
        ValidateCreds --> CreateClaims
        CreateClaims --> SignToken
        SignToken --> ReturnToken
    end
    
    subgraph Usage["Token Usage Process"]
        SendRequest[Client Sends Request with Bearer Token]
        ExtractHeader[Extract Authorization Header]
        ParseToken[Parse Bearer TOKEN]
        
        SendRequest --> ExtractHeader
        ExtractHeader --> ParseToken
    end
    
    subgraph Validation["Token Validation Process"]
        ExtractClaims[Extract Claims from Token]
        VerifySignature[Verify Token Signature]
        CheckExpiry[Check Token Expiration]
        LoadUserDetails[Load User Details from DB]
        CompareUsername[Compare Usernames]
        SetAuthentication[Set Security Context]
        
        ParseToken --> ExtractClaims
        ExtractClaims --> VerifySignature
        VerifySignature --> CheckExpiry
        CheckExpiry --> LoadUserDetails
        LoadUserDetails --> CompareUsername
        CompareUsername --> SetAuthentication
    end
    
    TokenGen --> Generation
    TokenUse --> Usage
    TokenVal --> Validation
    
    Generation --> Usage
    Usage --> Validation
```

<div dir="rtl">

## הגדרות JWT ב-Stage 2 - JWT Configuration

</div>

```mermaid
graph TD
    JwtProperties[JwtProperties Configuration]
    
    subgraph Properties["JWT Properties"]
        ExpTime[EXPIRATION_TIME<br/>300,000 ms = 5 minutes]
        TokenPrefix[TOKEN_PREFIX<br/>Bearer ]
        HeaderString[HEADER_STRING<br/>Authorization]
    end
    
    subgraph JwtUtilConfig["JwtUtil Configuration"]
        KeyGen[KeyGenerator<br/>HmacSHA256 Algorithm]
        SecretKey[Secret Key Generation<br/>On Application Start]
        TokenStructure[JWT Token Structure]
    end
    
    subgraph TokenClaims["Token Claims Structure"]
        Subject[Subject: username]
        IssuedAt[Issued At: current timestamp]
        Expiration[Expiration: +5 minutes]
        Roles[Roles: user authorities with ROLE_ prefix]
        IssuedBy[Issued By: learning JWT with Spring Security]
    end
    
    subgraph FilterConfig["Filter Configuration"]
        FilterChain[SecurityFilterChain]
        JwtFilterPos[JwtAuthenticationFilter position<br/>Before UsernamePasswordAuthenticationFilter]
        AuthRules[Authorization Rules<br/>permitAll vs hasAnyRole]
    end
    
    JwtProperties --> Properties
    JwtUtilConfig --> KeyGen
    JwtUtilConfig --> SecretKey
    JwtUtilConfig --> TokenStructure
    TokenStructure --> TokenClaims
    
    Properties --> JwtUtilConfig
    Properties --> FilterConfig
    JwtUtilConfig --> FilterConfig
```

<div dir="rtl">

## השוואת ההבדלים בקוד - Code Differences

</div>

```mermaid
graph LR
    subgraph Stage1["Stage 1 - Basic JWT"]
        S1Auth[AuthenticationController<br/>POST /login only]
        S1Jwt[JwtUtil<br/>generateToken only]
        S1Sec[SecurityConfig<br/>Basic CORS + Sessions]
        S1NoFilter[No JWT Filter]
        S1NoVal[No Token Validation]
    end
    
    subgraph Stage2["Stage 2 - Complete JWT"]
        S2Auth[AuthenticationController<br/>POST /api/login]
        S2User[UserController<br/>GET /api/protected-message]
        S2Jwt[JwtUtil<br/>generateToken + validateToken<br/>+ extractUsername + more]
        S2Filter[JwtAuthenticationFilter<br/>Token Processing]
        S2Sec[SecurityConfig<br/>JWT Filter + Role-based Auth]
        S2Props[JwtProperties<br/>TOKEN_PREFIX + HEADER_STRING]
    end
    
    Stage1 -.->|Upgrade| Stage2
    
    S1Auth -.->|Enhanced| S2Auth
    S1Jwt -.->|Extended| S2Jwt
    S1Sec -.->|Enhanced| S2Sec
    S1NoFilter -.->|Added| S2Filter
    S1NoVal -.->|Added| S2Props
```

<div dir="rtl">

## מתודולוגיית הAuth ב-Stage 2

### 1. Token Generation
- משתמש מתחבר עם username/password
- המערכת מאמתת פרטים מול DB
- JwtUtil יוצר token חתום עם claims
- Token מוחזר ללקוח

### 2. Token Usage
- לקוח שולח token ב-Authorization header
- JwtAuthenticationFilter מיירט כל בקשה
- מחלץ token מ-"Bearer TOKEN"
- מאמת token ומטען SecurityContext

### 3. Protected Access
- Spring Security בודק SecurityContext
- מאפשר גישה על בסיס roles
- hasAnyRole("USER", "ADMIN") לendpoints מוגנים

### 4. Token Validation
- בדיקת חתימה דיגיטלית
- בדיקת תפוגה (5 דקות)
- בדיקת username matching
- טיפול בשגיאות עם 401/500

</div>