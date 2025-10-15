# תיעוד מחלקת JwtUtil עם תרשימי תהליכים

<div dir="rtl">

## הקדמה

### מה זה JwtUtil?

**JwtUtil** היא מחלקת עזר מרכזית המטפלת בכל הפעולות הקשורות ל-JSON Web Tokens (JWT) באפליקציית Spring Boot. המחלקה אחראית על יצירה, אימות וחילוץ מידע מטוקנים.

### תפקידי המחלקה

המחלקה מספקת את השירותים הבאים:
- **יצירת טוקנים חדשים** - בעת הרשמה או כניסה של משתמשים
- **אימות טוקנים קיימים** - בדיקה שהטוקן תקין, לא פג תוקף ולא זויף
- **חילוץ מידע מטוקנים** - קבלת שם משתמש, תאריך תפוגה ונתונים נוספים
- **ניהול מפתח הצפנה** - יצירה ושמירה של המפתח הסודי

### רכיבים עיקריים

1. **Secret Key** - מפתח הצפנה ייחודי לכל הפעלה של האפליקציה
2. **Token Generation** - יצירת טוקנים עם claims מותאמים אישית
3. **Token Validation** - אימות הטוקן כולל חתימה ותוקף
4. **Claims Extraction** - חילוץ נתונים ספציפיים מהטוקן

---

## 1. אתחול המחלקה ויצירת המפתח

### הסבר התהליך
כאשר האפליקציה נטענת, Spring יוצר instance של JwtUtil. בconstructor מתבצעת יצירה של מפתח הצפנה ייחודי שישמש לכל הטוקנים באפליקציה.

**חשיבות המפתח:**
- כל טוקן נחתם במפתח הזה
- בלי המפתח הנכון אי אפשר לאמת או ליצור טוקנים
- המפתח נוצר רנדומלית בכל הפעלה (לא שמור בקובץ)

```mermaid
flowchart TD
    A[התחלת האפליקציה] --> B[Spring יוצר instance של JwtUtil]
    B --> C[קריאה ל-Constructor]
    C --> D[יצירת KeyGenerator לאלגוריתם HmacSHA256]
    D --> E[יצירת מפתח סודי רנדומלי]
    E --> F[המרה למפתח HMAC]
    F --> G[שמירת המפתח במשתנה key]
    G --> H[המחלקה מוכנה לשימוש]
```

---

## 2. תהליך יצירת טוקן חדש

### הסבר התהליך
כאשר משתמש מתחבר בהצלחה, המערכת יוצרת טוקן JWT חדש שמכיל את פרטי המשתמש והרשאותיו. הטוקן נחתם במפתח הסודי ונשלח ללקוח.

**מה כלול בטוקן:**
- **Subject** - שם המשתמש
- **IssuedAt** - מתי הטוקן נוצר
- **Expiration** - מתי הטוקן יפוג
- **Roles** - הרשאות המשתמש
- **Custom Claims** - מידע נוסף כמו "issuedBy"

```mermaid
flowchart TD
    A[קריאה ל-generateToken] --> B[קבלת AuthenticationRequest ו-UserDetails]
    B --> C[יצירת Map ריק לclaims נוספים]
    C --> D[יצירת JWT Builder]
    D --> E[הוספת subject - שם המשתמש]
    E --> F[הוספת issuedAt - זמן נוכחי]
    F --> G[הוספת expiration - זמן נוכחי + EXPIRATION_TIME]
    G --> H[חילוץ רשימת roles מ-UserDetails]
    H --> I[הוספת roles כ-claim]
    I --> J[הוספת issuedBy כ-claim]
    J --> K[חתימה על הטוקן במפתח הסודי]
    K --> L[המרה לstring מוכן לשליחה]
    L --> M[החזרת הטוקן ללקוח]
```

---

## 3. תהליך אימות טוקן

### הסבר התהליך
כאשר לקוח שולח בקשה עם טוקן, המערכת צריכה לוודא שהטוקן תקין. התהליך כולל בדיקת חתימה, תוקף ושם משתמש.

**שלבי האימות:**
1. **חילוץ שם המשתמש** מהטוקן
2. **השוואה** עם שם המשתמש ב-UserDetails
3. **בדיקת תוקף** - שהטוקן לא פג
4. **אימות חתימה** - שהטוקן לא זויף

**טיפול בשגיאות:**
- טוקן פג תוקף → `false`
- חתימה לא תקינה → `false`
- טוקן פגום → `false`
- שגיאה טכנית → `RuntimeException`

```mermaid
flowchart TD
    A[קריאה ל-validateToken] --> B[קבלת token ו-UserDetails]
    B --> C[try block - התחלת אימות]
    C --> D[חילוץ username מהטוקן]
    D --> E{האם חילוץ הצליח?}
    E -->|לא| F{סוג השגיאה}
    E -->|כן| G[השוואת username עם UserDetails]
    G --> H[בדיקה שהטוקן לא פג תוקף]
    H --> I{האם שם המשתמש תואם והטוקן לא פג?}
    I -->|כן| J[החזרת true - טוקן תקין]
    I -->|לא| K[החזרת false - טוקן לא תקין]
    F -->|ExpiredJwtException| L[החזרת false - טוקן פג תוקף]
    F -->|SignatureException| M[החזרת false - חתימה לא תקינה]
    F -->|MalformedJwtException| N[החזרת false - טוקן פגום]
    F -->|שגיאה אחרת| O[זריקת RuntimeException - שגיאה טכנית]
```

---

## 4. מנגנון חילוץ Claims

### הסבר התהליך
JWT מכיל מידע מקודד שנקרא Claims. כדי לגשת למידע הזה, צריך לפענח את הטוקן ולחלץ את הנתונים הרצויים.

**סוגי Claims נפוצים:**
- **Subject** - שם המשתמש
- **Expiration** - תאריך תפוגה
- **IssuedAt** - תאריך יצירה
- **Roles** - הרשאות משתמש

```mermaid
flowchart TD
    A[בקשה לחילוץ claim] --> B[קריאה ל-extractClaim]
    B --> C[קבלת token ו-Function resolver]
    C --> D[קריאה ל-extractAllClaims]
    D --> E[קריאה ל-getKey לקבלת המפתח הסודי]
    E --> F[יצירת JWT Parser]
    F --> G[הגדרת המפתח לאימות חתימה]
    G --> H[פענוח הטוקן ואימות חתימה]
    H --> I{האם הפענוח הצליח?}
    I -->|לא| J[זריקת JWT Exception]
    I -->|כן| K[חילוץ ה-payload - כל הclaims]
    K --> L[הפעלת ה-resolver על הclaims]
    L --> M[החזרת הערך המבוקש]
```

---

## 5. בדיקת תוקף הטוקן

### הסבר התהליך
כל טוקן JWT יש לו תאריך תפוגה. הבדיקה משווה את תאריך התפוגה עם הזמן הנוכחי.

```mermaid
flowchart TD
    A[קריאה ל-isTokenExpired] --> B[חילוץ תאריך תפוגה מהטוקן]
    B --> C[קבלת הזמן הנוכחי]
    C --> D{האם תאריך התפוגה לפני הזמן הנוכחי?}
    D -->|כן| E[החזרת true - הטוקן פג תוקף]
    D -->|לא| F[החזרת false - הטוקן עדיין תקף]
```

---

## 6. מחזור חיי הטוקן

### הסבר התרשים
תרשים זה מראה את כל המצבים שטוקן יכול להיות בהם מרגע יצירתו ועד השמדתו.

```mermaid
stateDiagram-v2
    [*] --> Created: יצירת טוקן חדש
    Created --> Active: טוקן נשלח ללקוח
    
    Active --> Validating: בקשה עם טוקן
    Validating --> Valid: אימות הצליח
    Validating --> Expired: טוקן פג תוקף
    Validating --> Invalid: חתימה לא תקינה
    Validating --> Malformed: טוקן פגום
    Validating --> TechnicalError: שגיאה טכנית
    
    Valid --> Active: טוקן עדיין פעיל
    Valid --> Expired: הגיע זמן התפוגה
    
    Expired --> [*]: הטוקן לא תקף יותר
    Invalid --> [*]: הטוקן נדחה
    Malformed --> [*]: הטוקן נדחה  
    TechnicalError --> [*]: שגיאה במערכת
```

---

## 7. ארכיטקטורת המחלקה

### הסבר התרשים
תרשים זה מראה איך המתודות במחלקה קוראות זו לזו ואיך הן מתקשרות עם רכיבים חיצוניים.

```mermaid
flowchart TD
    A[JwtUtil Constructor] --> B[KeyGenerator]
    B --> C[Secret Key]
    
    D[generateToken] --> E[Jwts.builder]
    D --> F[UserDetails]
    D --> C
    
    G[validateToken] --> H[extractUsername]
    G --> I[isTokenExpired]
    G --> J[UserDetails comparison]
    
    H --> K[extractClaim]
    I --> L[extractExpiration]
    L --> K
    
    K --> M[extractAllClaims]
    M --> N[Jwts.parser]
    M --> C
    
    O[External Filter] --> G
    O --> H
    P[Authentication Controller] --> D
```

---

## 8. טיפול בשגיאות ברמות שונות

### הסבר התהליך
המחלקה מבדילה בין סוגי שגיאות שונים ומטפלת בהם בהתאם לחומרתן.

```mermaid
flowchart TD
    A[פעולה על טוקן] --> B{סוג הפעולה}
    B -->|validateToken| C[אימות טוקן]
    B -->|extractUsername| D[חילוץ שם משתמש]
    B -->|generateToken| E[יצירת טוקן]
    
    C --> F{תוצאת האימות}
    F -->|ExpiredJwtException| G[return false - טוקן פג תוקף]
    F -->|SignatureException| H[return false - חתימה לא תקינה]
    F -->|MalformedJwtException| I[return false - טוקן פגום]
    F -->|Exception אחר| J[throw RuntimeException - שגיאה טכנית]
    F -->|הצלחה| K[return true - טוקן תקין]
    
    D --> L{תוצאת החילוץ}
    L -->|הצלחה| M[החזרת שם המשתמש]
    L -->|JWT Exception| N[זריקת Exception למעלה]
    
    E --> O{תוצאת היצירה}
    O -->|הצלחה| P[החזרת טוקן חדש]
    O -->|שגיאה| Q[זריקת RuntimeException]
```

---

## סיכום ועקרונות מנחים

### עקרונות תכנון המחלקה

1. **Single Responsibility** - המחלקה עוסקת רק בJWT, לא באימות משתמשים
2. **Fail Fast** - שגיאות מתגלות מיד ולא מסתתרות
3. **Clear Error Handling** - הבדלה ברורה בין שגיאות אימות לשגיאות טכניות
4. **Stateless Operations** - כל פעולה עצמאית, לא תלויה במצב קודם

### דפוסי שימוש נפוצים

**ביצירת טוקן:**

</div>

```java
// בController של Authentication
String token = jwtUtil.generateToken(authRequest, userDetails);
```

<div dir="rtl">

**באימות טוקן:**

</div>

```java
// בJWT Filter
if (jwtUtil.validateToken(token, userDetails)) {
    // הגדרת authentication
}
```

<div dir="rtl">

**בחילוץ מידע:**

</div>

```java
// בכל מקום שצריך את שם המשתמש
String username = jwtUtil.extractUsername(token);
```

<div dir="rtl">

### שיקולי ביטחון חשובים

1. **מפתח רנדומלי** - נוצר מחדש בכל הפעלה של האפליקציה
2. **אימות חתימה** - כל טוקן נבדק שלא זויף
3. **בדיקת תוקף** - טוקנים פגי תוקף נדחים אוטומטית
4. **טיפול בשגיאות** - לא חושף מידע רגיש בהודעות שגיאה

### נקודות לשיפור אפשריות

1. **שמירת מפתח קבוע** - כרגע המפתח משתנה בכל הפעלה
2. **הגדרת זמני תוקף גמישים** - לפי סוג משתמש או פעולה
3. **רישום שגיאות** - לוגים מפורטים לצורכי אבחון
4. **תמיכה בrefresh tokens** - לחידוש טוקנים בלי התחברות מחדש

</div>