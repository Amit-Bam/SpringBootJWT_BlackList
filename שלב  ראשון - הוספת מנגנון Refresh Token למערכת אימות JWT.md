// java
package com.example.jwt_basics1.service;

import com.example.jwt_basics1.config.JwtUtil;
import com.example.jwt_basics1.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.UserDetails;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;

    public AuthenticationResponse refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new IllegalArgumentException("Refresh token is missing");
        }

        String username = jwtUtil.extractUsername(refreshToken);
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        if (!jwtUtil.validateToken(refreshToken, userDetails)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        // generate new tokens (generateToken accepts AuthenticationRequest in current JwtUtil; pass null)
        String newAccessToken = jwtUtil.generateToken(null, userDetails);
        String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);

        return new AuthenticationResponse(newAccessToken, newRefreshToken);
    }
}<div dir="rtl">

# ביצוע תרגיל הוספת Refresh Token

## תוכן העניינים
1. [הסבר על האפליקציה הקיימת (Stage2)](#הסבר-על-האפליקציה-הקיימת-stage2)
2. [תרגיל: הוספת מנגנון Refresh Token למערכת אימות JWT](#תרגיל-הוספת-מנגנון-refresh-token-למערכת-אימות-jwt)
3. [שלבי הביצוע](#שלבים-לביצוע)
4. [בדיקת המערכת](#בדיקת-המערכת)
5. [שיקולי אבטחה והרחבות](#שיקולי-אבטחה-נוספים)
6. [סיכום](#סיכום)

---

## הסבר על האפליקציה הקיימת (Stage2)

### סקירה כללית
התוכנית היא אפליקציית Spring Boot המשתמשת באימות JWT (JSON Web Token) כדי להגן על נתיבים מסוימים ולוודא שמשתמשים מאומתים.

האימות מתבצע ללא שימוש במצב Session (**Stateless Authentication**) מה שהופך את האפליקציה ליותר מתאימה ל-API מבוסס REST.

### מרכיבי התוכנית העיקריים

1. **מחלקת `JwtUtil`**: אחראית ליצירה, אימות והפקת מידע מתוך ה-JWT
2. **מחלקת `JwtAuthenticationFilter`**: פילטר מותאם אישית המורץ על כל בקשה נכנסת, מאמת את ה-JWT ומגדיר את ההקשר האבטחתי (Security Context) בהתאם
3. **מחלקת `AuthenticationController`**: מטפלת בבקשות התחברות ומחזירה JWT למשתמש לאחר אימות הצלחה
4. **מחלקת `SecurityConfig`**: מגדירה את קונפיגורציית האבטחה של האפליקציה, כולל אילו נתיבים מוגנים ואילו לא
5. **מחלקת `CustomUserDetailsService`**: טוענת את פרטי המשתמש מתוך בסיס הנתונים לצורך האימות
6. **מחלקת `DataLoader`**: טוענת נתוני משתמשים ותרחישים ראשוניים לבסיס הנתונים בעת הפעלת האפליקציה

### איך המערכת עובדת

#### התחברות וקבלת JWT

**בקשת התחברות:** המשתמש שולח בקשת POST לנתיב `login/` עם שם משתמש וסיסמה.

**אימות המשתמש:**
- `AuthenticationController` מקבל את הבקשה ומעביר את פרטי המשתמש ל-`AuthenticationService`
- `AuthenticationService` משתמש ב-`CustomUserDetailsService` כדי לטעון את פרטי המשתמש מבסיס הנתונים
- בודק שהסיסמה שסופקה תואמת לסיסמה המאוחסנת (לאחר הצפנה)

**יצירת JWT:**
- אם האימות מצליח, `JwtUtil` יוצר JWT המכיל את שם המשתמש, תפקידים ומידע נוסף
- ה-JWT נחתם באמצעות מפתח סודי (Secret Key) כדי למנוע זיוף

**החזרת JWT:**
- ה-JWT מוחזר ללקוח בתוך גוף התגובה (Response Body)

#### גישה לנתיבים מוגנים

**בקשה לנתיב מוגן:**
המשתמש מנסה לגשת לנתיב מוגן (לדוגמה, `home/`), ושולח את ה-JWT בכותרת Authorization בפורמט:

<div dir="ltr">

```
Bearer <token>
```

</div>

**פילטר `JwtAuthenticationFilter`:**
לפני שהבקשה מגיעה לבקר (Controller), `JwtAuthenticationFilter` מפענח את ה-JWT מהכותרת.

משתמש ב-`JwtUtil` כדי לאמת את ה-JWT:
- **אימות חתימה:** מוודא שה-JWT נחתם במפתח הסודי הנכון
- **אימות תוקף:** בודק שה-JWT לא פג תוקף
- **אימות משתמש:** בודק שהמשתמש קיים במערכת

**הגדרת ההקשר האבטחתי:**
אם ה-JWT תקין, הפילטר יוצר אובייקט Authentication ומגדיר אותו ב-`SecurityContextHolder`

**גישה לנתיב:**
הבקשה ממשיכה לבקר, כאשר כעת המערכת יודעת שהמשתמש מאומת ויכולה להחליט האם לאפשר גישה לנתיב בהתאם לתפקידיו.

### קונפיגורציית אבטחה (SecurityConfig)

- **השבתת CSRF:** מכיוון שהאימות הוא Stateless, אין צורך בהגנת CSRF
- **הגדרת CORS:** מאפשר בקשות ממקורות שונים (לדוגמה, שימוש באפליקציית React)
- **ניהול Session:** מוגדר כ-`SessionCreationPolicy.STATELESS` כדי לוודא שהשרת לא יוצר Session
- **הרשאות גישה:**
    - נתיב `login/` מוגדר כ-`permitAll()`, כך שכל אחד יכול לגשת אליו ללא אימות
    - נתיב `home/` מוגדר כ-`hasAnyRole("USER", "ADMIN")`, כך שרק משתמשים עם אחד מהתפקידים הללו יכולים לגשת
- **הוספת הפילטר:** הוספת `JwtAuthenticationFilter` לשרשרת הפילטרים לפני `UsernamePasswordAuthenticationFilter`

### תרשים זרימה של התהליך

1. **התחברות:**
    - משתמש שולח בקשת התחברות ל-`login/`
    - אם האימות מצליח, מוחזר JWT

2. **גישה לנתיב מוגן:**
    - משתמש שולח בקשה לנתיב מוגן עם ה-JWT בכותרת
    - הפילטר מאמת את ה-JWT ומאפשר גישה אם הוא תקין

3. **אימות ה-JWT:**
    - בדיקת חתימה ותוקף
    - בדיקת קיום המשתמש

4. **הגדרת Authentication Context:**
    - הגדרת פרטי המשתמש ב-`SecurityContext` כדי שניתן יהיה להשתמש בהם בהמשך הבקשה

### נקודות חשובות

- **Stateless Authentication:** האפליקציה לא שומרת מצב (Session), וכל בקשה מכילה את ה-JWT לאימות
- **אבטחת ה-JWT:**
    - חשוב לשמור על המפתח הסודי בצורה מאובטחת ולא לחשוף אותו
    - (באופן כללי: מומלץ להשתמש ב-HTTPS כדי למנוע יירוט של ה-JWT אך לא ניישם זאת במסגרת פרויקט)
- **תוקף ה-JWT:** ה-JWT מוגבל בזמן (לדוגמה, 30 דקות), ולאחר מכן המשתמש יצטרך להתחבר מחדש או להשתמש במנגנון ריענון (שנוסף מאוחר יותר)

### סיכום

לפני הוספת מנגנון ה-Refresh Token, התוכנית סיפקה אימות בסיסי באמצעות JWT. המשתמשים יכלו להתחבר, לקבל JWT, ולהשתמש בו כדי לגשת לנתיבים מוגנים. האימות היה Stateless והאפליקציה לא ניהלה Sessions. מנגנון זה מתאים לאפליקציות RESTful אך ללא מנגנון ריענון, המשתמשים יצטרכו להתחבר מחדש בכל פעם שה-JWT פג תוקף.

---

## תרגיל: הוספת מנגנון Refresh Token למערכת אימות JWT

### מבוא
במערכת האימות הנוכחית, משתמשים מקבלים Access Token (JWT) לאחר התחברות מוצלחת. ה-Access Token משמש לאימות המשתמש בבקשות עתידיות. עם זאת, כאשר ה-Access Token פג תוקף, המשתמש נדרש להתחבר מחדש. כדי לשפר את חוויית המשתמש ולמנוע התחברויות חוזרות, נשתמש במנגנון **Refresh Token**.

ה-Refresh Token הוא טוקן ארוך טווח המאפשר לקבל Access Token חדש כאשר הישן פג תוקף, ללא צורך בהתחברות מחדש.

### מטרת התרגיל
להוסיף למערכת האימות מנגנון Refresh Token המאפשר למשתמשים לקבל Access Token חדש כאשר הישן פג תוקף, תוך שמירה על אבטחת המערכת.

---

## שלבים לביצוע

### 1. עדכון קובץ ההגדרות (JwtProperties)
ראשית, נוסיף קבועים עבור זמני התפוגה של ה-Access Token וה-Refresh Token.

### 2. עדכון מחלקת JwtUtil
נוסיף שיטה ליצירה של Refresh Tokens.

### 3. עדכון מחלקת AuthenticationService
נעדכן את המחלקה כדי להחזיר גם Refresh Token בעת התחברות.

### 4. יצירת/הרחבת DTO עבור בקשת Refresh Token
ניצור/נעדכן מחלקה שתחזיק את ה-Refresh Token הנשלח בבקשה.

### 5. יצירת שירות עבור ריענון הטוקנים (RefreshTokenService)
ניצור שירות שיטפל בלוגיקה של ריענון הטוקנים.

### 6. עדכון AuthenticationController
נוסיף נקודת קצה (endpoint) שתטפל בבקשות לריענון הטוקנים.

### 7. עדכון קונפיגורציית האבטחה (SecurityConfig)
נאפשר גישה ללא אימות לנתיב `refresh-token/` ונעדכן את הפילטר.

### 8. עדכון JwtAuthenticationFilter
נגרום לפילטר לדלג על נתיב `refresh_token/`:

<div dir="ltr">

```java
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.equals("/login") || path.equals("/refresh_token");
    }

    // שאר הקוד של הפילטר...
}
```

</div>

---

## בדיקת המערכת

### בדיקת התחברות וקבלת טוקנים
שלחו בקשת POST ל-`login/` עם שם משתמש וסיסמה.
וודאו שאתם מקבלים גם Access Token וגם Refresh Token.

<div dir="ltr">

```http
POST http://localhost:8080/login
Content-Type: application/json

{
	"username": "admin",
	"password": "admin"
}
```

</div>

### בדיקת גישה לנתיב מוגן
השתמשו ב-Access Token כדי לגשת לנתיב מוגן (לדוגמה, `/home`).
וודאו שהגישה מאושרת.

<div dir="ltr">

```http
GET http://localhost:8080/home
Authorization: Bearer HERE_WE_PUT_THE_ACCESS_TOKEN
```

</div>

### בדיקת רענון הטוקנים
לאחר שפג תוקפו של ה-Access Token (או קיצרו את זמן התפוגה לצורך הבדיקה), שלחו בקשת POST ל-`refresh-token/` עם ה-Refresh Token.
וודאו שאתם מקבלים Access Token ו-Refresh Token חדשים.

<div dir="ltr">

```http
POST http://localhost:8080/refresh_token
Content-Type: application/json

{
	"refreshToken": "HERE_WE_PUT_THE_REFRESH_TOKEN"
}
```

</div>

### בדיקת גישה עם הטוקן החדש
השתמשו ב-Access Token החדש כדי לגשת לנתיב מוגן.
וודאו שהגישה מאושרת.

---

## שיקולי אבטחה נוספים

### אחסון מאובטח של הטוקנים
וודאו שהלקוח מאחסן את הטוקנים בצורה מאובטחת.

### מניעת שימוש חוזר ב-Refresh Token
שקלו ליישם מנגנון המונע שימוש חוזר ב-Refresh Token (**Refresh Token Rotation**).

### הרחבות אפשריות
הוספת נתיב ליציאה (Logout) המבטל את ה-Refresh Token של המשתמש.

---

## סיכום

בתרגיל זה, הוספתם למערכת האימות שלכם מנגנון Refresh Token המאפשר למשתמשים לקבל Access Token חדש ללא צורך בהתחברות מחדש. המנגנון משפר את חוויית המשתמש ומגביר את אבטחת המערכת.

### יתרונות המנגנון:
- **שיפור חוויית המשתמש:** אין צורך בהתחברות מחדש כאשר ה-Access Token פג תוקף
- **אבטחה משופרת:** Access Token קצר טווח מקטין את הסיכון במקרה של פשרה
- **גמישות:** ניתן לבטל Refresh Token במקרה הצורך
- **בקרה:** השרת שומר שליטה על מחזור החיים של הטוקנים

### נקודות מפתח לזכור:
1. **Access Token קצר טווח** (15-30 דקות)
2. **Refresh Token ארוך טווח** (ימים)
3. **אימות זהות** לפני מתן טוקנים חדשים
4. **ביטול טוקנים** במקרה של חשד לפשרה
5. **אחסון מאובטח** בצד הלקוח

המערכת כעת מוכנה לשימוש מתקדם יותר עם יכולות ניהול טוקנים מתקדמות!

</div>