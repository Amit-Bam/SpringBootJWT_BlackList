# איך JWT עובד במערכת 

<div dir="rtl">

## מה זה JWT?

**JWT (JSON Web Token)** הוא סטנדרט פתוח (RFC 7519) להעברת מידע בטוח בין צדדים כ-JSON object. ה-token מכיל שלושה חלקים מופרדים בנקודות:

</div>

```
header.payload.signature
```

<div dir="rtl">

## מבנה JWT במערכת 

</div>

### Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload (Claims)
```json
{
  "sub": "admin",                                    // username
  "iat": 1640995200,                                // issued at timestamp
  "exp": 1640995500,                                // expiration (5 minutes later)
  "roles": ["ROLE_ADMIN", "ROLE_USER"],            // user authorities
  "issuedBy": "learning JWT with Spring Security"   // custom claim
}
```

### Signature
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secretKey
)
```

<div dir="rtl">

## תהליך יצירת ה-JWT במערכת 

### 1. אתחול המפתח (JwtUtil Constructor)

</div>

```java
public JwtUtil() {
    KeyGenerator secretKeyGen = KeyGenerator.getInstance("HmacSHA256");
    this.key = Keys.hmacShaKeyFor(secretKeyGen.generateKey().getEncoded());
}
```

<div dir="rtl">

**מה קורה כאן:**
- נוצר מפתח חדש בכל הפעלה של האפליקציה
- המפתח משמש לחתימה ואימות של ה-tokens
- המפתח מאוחסן בזיכרון כ-field בקלאס

### 2. יצירת Token (generateToken method)

</div>

```java
public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    
    return Jwts.builder()
            .claims().add(claims)
            .subject(userDetails.getUsername())                    // שם המשתמש
            .issuedAt(new Date(System.currentTimeMillis()))       // זמן יצירה
            .expiration(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) // תוקף 5 דקות
            .and()
            .claim("roles", userDetails.getAuthorities().stream()  // תפקידי המשתמש
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()))
            .claim("issuedBy", "learning JWT with Spring Security") // claim נוסף
            .signWith(getKey())                                    // חתימה עם המפתח
            .compact();                                            // הפיכה ל-string
}
```

<div dir="rtl">

## זרימת Authentication במערכת

### שלב 1: קבלת בקשת Login

</div>

```java
@PostMapping("/login")
public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequest authenticationRequest)
```

<div dir="rtl">

- הלקוח שולח POST request ל-`/login`
- הבקשה מכילה username ו-password ב-JSON

### שלב 2: טעינת פרטי המשתמש

</div>

```java
UserDetails userDetails = customUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
```

<div dir="rtl">

**מה קורה ב-CustomUserDetailsService:**

</div>

```java
public UserDetails loadUserByUsername(String username) {
    User user = userRepository.findByUsername(username);    // חיפוש במסד הנתונים
    
    if (user != null) {
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),                         // סיסמה מוצפנת
                mapRolesToAuthorities(user.getRoles())      // המרת roles ל-authorities
        );
    }
    return null;
}
```

<div dir="rtl">

### שלב 3: אימות סיסמה

</div>

```java
if (!passwordEncoder.matches(authenticationRequest.getPassword(), userDetails.getPassword())) {
    throw new AuthenticationServiceException("Invalid credentials");
}
```

<div dir="rtl">

- השוואה בין הסיסמה שהוזנה לסיסמה המוצפנת במסד הנתונים
- שימוש ב-BCryptPasswordEncoder

### שלב 4: יצירת JWT Token

</div>

```java
String jwtToken = jwtUtil.generateToken(userDetails);
```

<div dir="rtl">

### שלב 5: החזרת התגובה

</div>

```java
return new AuthenticationResponse(jwtToken);
```

<div dir="rtl">

## הגדרות Security

### CORS Configuration

</div>

```java
.cors(cors -> {
    cors.configurationSource(request -> {
        var corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(List.of("http://localhost:5173"));  // React app
        corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfig.setAllowedHeaders(List.of("*"));
        return corsConfig;
    });
})
```

<div dir="rtl">

### Session Management

</div>

```java
.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```

<div dir="rtl">

- **STATELESS** = האפליקציה לא תשמור sessions
- כל בקשה חייבת להכיל JWT token

### Authorization Rules

</div>

```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/login/**").permitAll()    // login נגיש לכולם
    .anyRequest().authenticated()                // כל שאר הבקשות דורשות אימות
);
```

<div dir="rtl">

## מחזור חיי ה-JWT

### 1. יצירה (Token Generation)
- לאחר login מצליח
- Token תקף ל-5 דקות (300,000 מילישניות)

### 2. שימוש (Token Usage)
- הלקוח שומר את ה-token (בדרך כלל ב-localStorage או memory)
- שולח את ה-token בכל בקשה ב-Authorization header:

</div>

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

<div dir="rtl">

### 3. תפוגה (Token Expiration)
- לאחר 5 דקות ה-token לא תקף
- הלקוח צריך להתחבר מחדש

## יתרונות הגישה הזו

### 1. Stateless
- השרת לא שומר מידע על sessions
- קל יותר לעשות scale-out

### 2. Security
- ה-token חתום דיגיטלית
- לא ניתן לזייף בלי המפתח הסודי

### 3. Self-contained
- כל המידע הדרוש נמצא ב-token עצמו
- לא צריך לפנות למסד נתונים לכל בקשה

### 4. Cross-domain
- עובד טוב עם SPA (Single Page Applications)
- תומך ב-CORS

## חולשות והגבלות

### 1. Token Size
- JWT tokens יכולים להיות גדולים (מכילים data)
- נשלחים בכל בקשה

### 2. Token Revocation
- לא ניתן לבטל token לפני תפוגתו
- צריך לחכות עד שיפוג

### 3. Key Management
- המפתח נוצר מחדש בכל הפעלה
- כל ה-tokens הקיימים יפסלו אחרי restart

### 4. Security Considerations
- המפתח בזיכרון - לא persistent
- לא מומלץ לייצור (צריך external key management)

</div>