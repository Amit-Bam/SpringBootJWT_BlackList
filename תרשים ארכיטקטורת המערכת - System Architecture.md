# תיעוד מערכת JWT - JWT System Documentation

<div dir="rtl">

## תרשים ארכיטקטורת המערכת - System Architecture

</div>

```mermaid
graph TB
    Client[Client Application<br/>React on localhost:5173]
    
    subgraph SpringBoot["Spring Boot Application"]
        direction TB
        Controller[AuthenticationController<br/>POST /login]
        Service[AuthenticationService]
        UserService[CustomUserDetailsService]
        JwtUtil[JwtUtil<br/>Token Generation]
        Security[SecurityConfig<br/>CORS & Security]
        
        subgraph Database["Database Layer"]
            UserRepo[UserRepository]
            RoleRepo[RoleRepository]
            UserEntity[User Entity]
            RoleEntity[Role Entity]
        end
    end
    
    MySQL[(MySQL Database<br/>schema_jwt_2024)]
    
    Client -->|HTTP POST /login| Controller
    Controller --> Service
    Service --> UserService
    Service --> JwtUtil
    UserService --> UserRepo
    UserRepo --> UserEntity
    UserEntity --> RoleEntity
    RoleEntity --> RoleRepo
    JwtUtil -->|JWT Token| Service
    Service -->|AuthenticationResponse| Controller
    Controller -->|JSON Response| Client
    
    UserRepo --> MySQL
    RoleRepo --> MySQL
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

## זרימת תהליך האימות - Authentication Flow

</div>

```mermaid
sequenceDiagram
    participant Client
    participant Controller as AuthenticationController
    participant Service as AuthenticationService
    participant UserService as CustomUserDetailsService
    participant JwtUtil
    participant UserRepo as UserRepository
    participant DB as MySQL Database
    
    Client->>Controller: POST /login {username, password}
    Controller->>Service: authenticate(authRequest)
    Service->>UserService: loadUserByUsername(username)
    UserService->>UserRepo: findByUsername(username)
    UserRepo->>DB: SELECT user with roles
    DB-->>UserRepo: User entity + roles
    UserRepo-->>UserService: User with roles
    UserService-->>Service: UserDetails object
    Service->>Service: validatePassword(password, hashedPassword)
    
    alt Password Valid
        Service->>JwtUtil: generateToken(userDetails)
        JwtUtil->>JwtUtil: createJWT with claims & expiration
        JwtUtil-->>Service: JWT token string
        Service-->>Controller: AuthenticationResponse(token)
        Controller-->>Client: 200 OK {accessToken}
    else Password Invalid
        Service-->>Controller: AuthenticationServiceException
        Controller-->>Client: 401 Unauthorized
    end
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
        +generateToken(UserDetails) String
        -getKey() Key
    }
    
    class SecurityConfig {
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
    
    class UserRepository {
        +findByUsername(String) User
        +findUserByUsername(String) User
    }
    
    class RoleRepository {
        +findRolesByUserId(Long) List~Role~
        +findByRoleName(String) Optional~Role~
    }
    
    AuthenticationController --> AuthenticationService
    AuthenticationService --> CustomUserDetailsService
    AuthenticationService --> JwtUtil
    CustomUserDetailsService --> UserRepository
    UserRepository --> User
    User --> Role
    RoleRepository --> Role
    AuthenticationController --> AuthenticationRequest
    AuthenticationController --> AuthenticationResponse
```

<div dir="rtl">

## תרשים זרימת נתונים - Data Flow Diagram

</div>

```mermaid
flowchart TD
    Start([Client sends login request])
    Validate{Validate credentials}
    LoadUser[Load user from database]
    CheckPassword{Password matches?}
    GenerateJWT[Generate JWT token]
    Success[Return JWT token]
    Failure[Return error]
    
    Start --> LoadUser
    LoadUser --> Validate
    Validate --> CheckPassword
    CheckPassword -->|Yes| GenerateJWT
    CheckPassword -->|No| Failure
    GenerateJWT --> Success
```

<div dir="rtl">

## תרשים רכיבי המערכת - System Components

</div>

```mermaid
graph LR
    subgraph Frontend["Frontend Layer"]
        React[React Application<br/>Port 5173]
    end
    
    subgraph Backend["Backend Layer"]
        direction TB
        
        subgraph Controllers["Controllers"]
            AuthController[AuthenticationController]
        end
        
        subgraph Services["Services"]
            AuthService[AuthenticationService]
            UserDetailsService[CustomUserDetailsService]
        end
        
        subgraph Config["Configuration"]
            SecurityConf[SecurityConfig]
            JwtConf[JwtUtil + JwtProperties]
        end
        
        subgraph Data["Data Layer"]
            Repositories[UserRepository<br/>RoleRepository]
            Entities[User Entity<br/>Role Entity]
        end
    end
    
    subgraph Database["Database Layer"]
        MySQL[MySQL Database]
    end
    
    React -->|HTTP Requests| AuthController
    AuthController --> AuthService
    AuthService --> UserDetailsService
    AuthService --> JwtConf
    UserDetailsService --> Repositories
    Repositories --> Entities
    Entities --> MySQL
    
    SecurityConf -.->|Configures| AuthController
    JwtConf -.->|Generates tokens| AuthService
```

<div dir="rtl">

## הגדרות JWT - JWT Configuration

</div>

```mermaid
graph TD
    JwtProperties[JwtProperties<br/>EXPIRATION_TIME = 5 minutes]
    KeyGen[KeyGenerator<br/>HmacSHA256 Algorithm]
    JwtUtil[JwtUtil Component]
    TokenStructure[JWT Token Structure]
    
    subgraph TokenClaims["Token Claims"]
        Subject[Subject: username]
        IssuedAt[Issued At: current time]
        Expiration[Expiration: +5 minutes]
        Roles[Roles: user authorities]
        IssuedBy[Issued By: learning JWT with Spring Security]
    end
    
    JwtProperties --> JwtUtil
    KeyGen --> JwtUtil
    JwtUtil --> TokenStructure
    TokenStructure --> TokenClaims
```

<div dir="rtl">

## נתוני בסיס הנתונים הראשוניים - Initial Data Setup

</div>

```mermaid
graph TD
    DataLoader[DataLoader Component<br/>CommandLineRunner]
    
    subgraph InitialData["Initial Database Data"]
        direction TB
        
        subgraph Roles["Roles Created"]
            AdminRole[ADMIN Role]
            UserRole[USER Role]
        end
        
        subgraph Users["Users Created"]
            AdminUser[Admin User<br/>username: admin<br/>password: admin<br/>roles: ADMIN, USER]
            RegularUser[Regular User<br/>username: user<br/>password: user<br/>roles: USER]
        end
    end
    
    DataLoader -->|Creates on startup| InitialData
    AdminRole --> AdminUser
    UserRole --> AdminUser
    UserRole --> RegularUser
```