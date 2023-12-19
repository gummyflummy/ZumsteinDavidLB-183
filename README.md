# ZumsteinDavidLB-183

## Einleitung
Dies ist die Leistungsbeurteilung von David Zumstein. Dieses Portfolio dient dazu, die Handlungsziele des Moduls 183 nachzuweisen. In diesem Modul geht es um die Applikationssicherheit. Jedes Handlungsziel hat ein eigenen Abschnitt mit jeweils einem Artefakt, welches ich erläuteren werde. 
Die Handlungsziele sehen wie folgt aus:



| Handlungsziel | Beschreibung                                                                                                                                                                             |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1             | Aktuelle Bedrohungen erkennen und erläutern können. Aktuelle Informationen zum Thema (Erkennung und Gegenmassnahmen) beschaffen und mögliche Auswirkungen aufzeigen und erklären können. |
| 2             | Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können. Gegenmassnahmen vorschlagen und implementieren können.                                                         |
| 3             | Mechanismen für die Authentifizierung und Autorisierung umsetzen können.                                                                                                                 |
| 4             | Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen.                                                                                            |
| 5             | Informationen für Auditing und Logging generieren. Auswertungen und Alarme definieren und implementieren.                                                                                |

## **_Handlungsziel 1_**

### Artefakt
Als Artefakt habe ich eine Tabelle der top 3 Bedrohungen erstellt. 

| Sicherheitsrisiko                          | Beschreibung                                              | Gegenmassnahmen                                                         | Auswirkungen                                                                        |
| ------------------------------------------ | -------------------------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Broken Access Control                      | Benutzer können ausserhalb ihrer zugewiesenen Berechtigungen handeln.   |Session-Verwaltung,  Verbesserte Zugriffskontrollen   | Unberechtigter Datenzugriff und Manipulation                |
| Cryptographic Failures                     | Sicherheitsmaßnahmen, um Daten zu schützen, funktionieren nicht richtig | die neusten Verschlüsselungsstandards benutzen, sensitive Informationen nicht unnötig speichern | Sensible Daten werden geklaut.                    |
| Injection                                  | unerlaubte Einschleusung von Daten oder Befehlen in einer Anwendung.                   | positive server-side input validation, sichere API nutzen, Eingabevalidierung         | unerlaubte Code ausführung                                |




Quelle: [https://owasp.org/Top10/](https://owasp.org/Top10/)

### wie habe ich das Handlungsziel erreicht?

Ich habe das Handlungsziel mit meiner Tabelle erreicht, da es darlegt, dass ich aktuelle Bedrohungen erkennen und erläutern kann. Ich habe jeweils ein Problem beschrieben und dann anschliessend die Auswirkungen und Gegenmassnahmen erläutert.

### Erklärung des Artefakts

Mein Artefakt ist eine Tabelle der Top 3 aktuellen Bedrohungen. Es wird jeweils kurz die Bedrohung beschrieben und dann anschliessend welche Auswirkungen so eine Bedrohung hat. Es werden auch Gegenmassnahmen erläutert um die Bedrohungen zu verhindern. Die Daten habe ich von einer Webseite, die wir in der Schule angeschaut haben, namens owasp. Sie zeigt die Statistiken der Top 10 Bedrohungen vom Jahr 2021. Ich habe die top 3 in meiner Tabelle eingebaut.

### Beurteilung des Artefakts
Mein Artefakt ist strukturiert und einfach zu lesen. Jedoch kann sie für einige kurz vorkommen. Ich hätte anstatt die Top 3 Bedrohungen einfach alle Bedrohungen auflisten können. Ich persönlich preferiere aber lieber eine kurze und knappe Tabelle, da für mich die Top 3 ausreichen. Für mich ist das Artefakt gut gelungen. Die Daten der owasp Webseite sind vertraulich.

## **_Handlungsziel 2_**

### Artefakt

Mein Artefakt ist die Code Veränderung im Auftrag LA_183_05_SQLInjection.

Vor der Veränderung:
```csharp
[HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'",
                request.Username,
                MD5Helper.ComputeMD5Hash(request.Password));

            User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();
            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }
```

nach der Veränderung:
```csharp
[HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string username = request.Username;
            string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

            User? user = _context.Users
                .Where(u => u.Username == username)
                .Where(u => u.Password == passwordHash)
                .FirstOrDefault();


            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }
```


### Wie wurde das Handlungsziel erreicht?

Ich habe das Handlungsziel erreicht indem ich mit der Veränderung des Codes eine bestehende Sicherheitslücke in einem Code behoben habe. Dies weist nach, dass ich eine Sicherheitslücke und ihre Ursache in einer Applikation erkennen konnte und anschliessend eine Gegenmassnahme vorgeschlagen und umgesetzt habe.

### Erklärung des Artefakts

Mein Artefakt zeigt Zwei Versionen eines Codes. In der ersten besteht die Gefahr von injections wie einer SQL injection. In der zweiten ist diese Gefahr behoben da die Eingaben des Benutzers nichtmehr direkt in die SQL-Abfrage eingefügt werden sondern als seperate Variable verwendet werden. Als Beispiel hätte man in der ersten Version als Passwort `--` schreiben können um sich als jeder belieber Benutzer einloggen zu können, selbst als Administrator.


### Beurteilung des Artefakts

Das Artefakt ist mir gut gelungen, wir hatten es 1 zu 1 so im Unterricht angeschaut, weswegen es keine grosse Herausforderung dargestellt hat. Das Artefakt ist ein gutes Beispiel für einen unsicheren und sicheren code, wobei man sagen muss, man kann einen Code so gut wie immer noch sicherer gestalten. Man könnte noch mehr Sicherheitsmassnahmen einbauen.

## **_Handlungsziel 3_**

### Artefakt
Als Artefakt benutze ich den Code von den Aufträgen: LA_183_11_Autorisierung und LA_183_12_Authentifizierung

```csharp
[HttpPost]
[ProducesResponseType(200)]
[ProducesResponseType(400)]
[ProducesResponseType(401)]
public ActionResult<User> Login(LoginDto request)
{
    if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
    {
        return BadRequest();
    }
    string username = request.Username;
    string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

    User? user = _context.Users
        .Where(u => u.Username == username)
        .Where(u => u.Password == passwordHash)
        .FirstOrDefault();

    if (user == null)
    {
        return Unauthorized("login failed");
    }

    if (user.SecretKey2FA != null)
    {
        string secretKey = user.SecretKey2FA;
        string userUniqueKey = user.Username + secretKey;
        TwoFactorAuthenticator authenticator = new TwoFactorAuthenticator();
        bool isAuthenticated = authenticator.ValidateTwoFactorPIN(userUniqueKey, request.UserKey);
        if (!isAuthenticated)
        {
            return Unauthorized("login failed");
        }
    }

    return Ok(CreateToken(user));
}

private string CreateToken(User user)
{
    string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
    string audience = _configuration.GetSection("Jwt:Audience").Value!;

    List<Claim> claims = new List<Claim> {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.Role,  (user.IsAdmin ? "admin" : "user"))
    };

    string base64Key = _configuration.GetSection("Jwt:Key").Value!;
    SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Key));

    SigningCredentials credentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.HmacSha512Signature);

    JwtSecurityToken token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        notBefore: DateTime.Now,
        expires: DateTime.Now.AddDays(1),
        signingCredentials: credentials
     );

    return new JwtSecurityTokenHandler().WriteToken(token);
}
```


### Wie wurde das Handlungsziel erreicht?

Das Handlungsziel wurde erreicht, indem ich in dem Artefakt, Mechanismen für die Authentifizierung und Autorisierung umgesetzt habe. Für die Autorisierung wurde JWT-Token umgesetzt und für die 2FA wurde google authenticator integriert

### Erklärung des Artefakts

Im Artefakt werden Nutzerdaten überprüft und als JWT-Token gespeichert um für Sicherheit zu sorgen. Zusätzlich wurde eine 2FA mittels google authenticator eingebaut um für mehr Sicherheit zu sorgen

### Beurteilung des Artefakts

JWT-Token und google authenticator zu benutzen sorgt für sehr viel Sichherheit, Plus es sind relativ simple Autorisierungs und Authentifizierungs Mechanismen. Das Artefakt ist gut gelungen, da es nun relativ sicher ist. Man könnte jedoch eventuell ein anderes Hashing benutzen.


## **_Handlungsziel 4_**

### Artefakt
Als Artefakt benutze ich den Code von dem Auftrag: LA_183_15_PasswortHashing

```csharp
[HttpPatch("password-update")]
[ProducesResponseType(200)]
[ProducesResponseType(400)]
[ProducesResponseType(404)]
public ActionResult PasswordUpdate(PasswordUpdateDto request)
{
    if (request == null)
    {
        return BadRequest("No request body");
    }

    var user = _context.Users.Find(request.UserId);
    if (user == null)
    {
        return NotFound(string.Format("User {0} not found", request.UserId));
    }

    if (user.Password != MD5Helper.ComputeMD5Hash(request.OldPassword))
    {
        return Unauthorized("Old password wrong");
    }

    string passwordValidation = validateNewPasswort(request.NewPassword);
    if (passwordValidation != "")
    {
        return BadRequest(passwordValidation);
    }

    user.IsAdmin = request.IsAdmin;
    user.Password = MD5Helper.ComputeMD5Hash(request.NewPassword);

    _context.Users.Update(user);
    _context.SaveChanges();

    return Ok("success");
}

private string validateNewPasswort(string newPassword)
{
    // Check small letter.
    string patternSmall = "[a-zäöü]";
    Regex regexSmall = new Regex(patternSmall);
    bool hasSmallLetter = regexSmall.Match(newPassword).Success;

    string patternCapital = "[A-ZÄÖÜ]";
    Regex regexCapital = new Regex(patternCapital);
    bool hasCapitalLetter = regexCapital.Match(newPassword).Success;

    string patternNumber = "[0-9]";
    Regex regexNumber = new Regex(patternNumber);
    bool hasNumber = regexNumber.Match(newPassword).Success;

    List<string> result = new List<string>();
    if (!hasSmallLetter)
    {
        result.Add("keinen Kleinbuchstaben");
    }
    if (!hasCapitalLetter)
    {
        result.Add("keinen Grossbuchstaben");
    }
    if (!hasNumber)
    {
        result.Add("keine Zahl");
    }

    if (result.Count > 0)
    {
        return "Das Passwort beinhaltet " + string.Join(", ", result);
    }
    return "";
}
```


### Wie wurde das Handlungsziel erreicht?

Das Handlungsziel wurde erreicht, indem das Artefakt ein starker Passwort Mechanismus besitzt. Es werden sicherheitsrelevante Aspekte berücksichtigt.

### Erklärung des Artefakts

Die Funktion für das Passwortupdate überprüft das Passwort, bevor es geändert wird, und führt eine Validierung des Passworts durch, damit das Passwort bestimmte Sicherheitsvorgaben erfüllt.

### Beurteilung des Artefakts

Das Artefakt besitzt einen sinnvollen Mechanismus. Jedoch könnte man noch mehr Sicherheitskriterien einbauen, da es momentan nur die Vorgaben Gross und Kleinbuchstaben sowie Zahlen gibt.



## **_Handlungsziel 5_**

### Artefakt

Als Artefakt benutze ich den Code von den Aufträgen: LA_183_17_Logging und LA_183_51_AuditTrail

```csharp
[Route("api/[controller]")]
[ApiController]
public class LoginController : ControllerBase
{
    private readonly ILogger _logger;
    private readonly NewsAppContext _context;
    private readonly IConfiguration _configuration;

    public LoginController(ILogger<LoginController> logger, NewsAppContext context, IConfiguration configuration)
    {
        _logger = logger;
        _context = context;
        _configuration = configuration;
    }

    /// <summary>
    /// Login a user using password and username
    /// </summary>
    /// <response code="200">Login successfull</response>
    /// <response code="400">Bad request</response>
    /// <response code="401">Login failed</response>
    [HttpPost]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public ActionResult<User> Login(LoginDto request)
    {
        if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
        {
            return BadRequest();
        }
        string username = request.Username;
        string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

        User? user = _context.Users
            .Where(u => u.Username == username)
            .Where(u => u.Password == passwordHash)
            .FirstOrDefault();

        if (user == null)
        {
            _logger.LogWarning($"login failed for user '{request.Username}'");
            return Unauthorized("login failed");
        }

        _logger.LogInformation($"login successful for user '{request.Username}'");
        return Ok(CreateToken(user));
    }

    private string CreateToken(User user)
    {
        string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
        string audience = _configuration.GetSection("Jwt:Audience").Value!;

        List<Claim> claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(ClaimTypes.Role,  (user.IsAdmin ? "admin" : "user"))
        };

        string base64Key = _configuration.GetSection("Jwt:Key").Value!;
        SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Key));

        SigningCredentials credentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha512Signature);

        JwtSecurityToken token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.Now,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials
         );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
```

Konfiguration:

```csharp
builder.Host.ConfigureLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole(); // Console Output
    logging.AddDebug(); // Debugging Console Output
});
```

Audit-Trail:

```csharp
    namespace M183.Migrations

{
/// <inheritdoc />
public partial class CreateTrigger : Migration
{
/// <inheritdoc />
protected override void Up(MigrationBuilder migrationBuilder)
{
migrationBuilder.CreateTable(
name: "NewsAudit",
columns: table => new
{
Id = table.Column<int>(type: "int", nullable: false)
.Annotation("SqlServer:Identity", "1, 1"),
NewsId = table.Column<int>(type: "int", nullable: false),
Action = table.Column<string>(type: "nvarchar(max)", nullable: false),
AuthorId = table.Column<int>(type: "int", nullable: false)
},
constraints: table =>
{
table.PrimaryKey("PK_NewsAudit", x => x.Id);
});

            migrationBuilder.Sql(@"CREATE TRIGGER news_insert ON dbo.News
                AFTER INSERT
                AS DECLARE
                  @NewsId INT,
                  @AuthorId INT;
                SELECT @NewsId = ins.ID FROM INSERTED ins;
                SELECT @AuthorId = ins.AuthorId FROM INSERTED ins;

                INSERT INTO NewsAudit (NewsId, Action, AuthorId) VALUES (@NewsId, 'Create', @AuthorId);");

            migrationBuilder.Sql(@"CREATE TRIGGER news_update ON dbo.News
                AFTER UPDATE
                AS DECLARE
                  @NewsId INT,
                  @AuthorId INT;
                SELECT @NewsId = ins.ID FROM INSERTED ins;
                SELECT @AuthorId = ins.AuthorId FROM INSERTED ins;

                INSERT INTO NewsAudit (NewsId, Action, AuthorId) VALUES (@NewsId, 'Update', @AuthorId);");


            migrationBuilder.Sql(@"CREATE TRIGGER news_delete ON dbo.News
                AFTER DELETE
                AS DECLARE
                  @NewsId INT,
                  @AuthorId INT;
                SELECT @NewsId = del.ID FROM DELETED del;
                SELECT @AuthorId = del.AuthorId FROM DELETED del;

                INSERT INTO NewsAudit (NewsId, Action, AuthorId) VALUES (@NewsId, 'Delete', @AuthorId);");

        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "NewsAudit");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS news_insert");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS news_update");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS news_delete");
        }
    }

}
```

### Wie wurde das Handlungsziel erreicht?

Das Handlungsziel wurde erreicht indem das Artefakt die Implementierung von Logging und die Einrichtung vom Audit-Trail umfasst.

### Erklärung des Artefakts

Als Logging wurde ILogger integriert umd Erreignisse zu protokollieren. EIn Audit-Trail wurde mittels Datenbank-Triggern implementiert um Änderungen zu protokollieren und zu speichern.

### Beurteilung des Artefakts

Das Artefakt benutzt gute Methoden. ILogger ist eine sehr bekannte Methode für das logging von Informationen, plus die Verwendung von SQL Server Triggers für das Auditing ist auch eine flotte Methode um Änderungen zu protokollieren und zu speichern. So wie Immer bin ich mir aber sicher, dass es besser geht. Man könnte zum Beispiel mehr kriterien für die Informationen angeben die protokoliiert werden sollten.



## Selbsteinschätzung des Erreichungsgrades der Kompetenz des Moduls
Geben Sie eine Selbsteinschätzung zu der Kompetenz in diesem Modul ab. Schätzen Sie selbst ein, inwiefern Sie die Kompetenz dieses Moduls erreicht haben und inwiefern nicht. Es geht in diesem Abschnitt nicht darum, auf die einzelnen Handlungsziele einzugehen. Das haben Sie bereits gemacht. Begründen Sie ihre Aussagen.

Ich habe die Kompetenz dieses Moduls erreicht. Der Unterricht hat alles sehr gründlich und gut abgedeckt. Unser Lehrer hat dafür gesorgt, dass wir dieses Modul verstehen, was ich sehr gut finde. Was Mein Portfolio-Eintrag angeht bin ich mir nicht sicher. Ich habe probiert so gut wie möglich die Handlungszielen mit Artefakten nachzuweisen und habe mich an die Portfolio Vorschriften gehalten. All meine Artefakte sind jedoch von den Arbeitsaufträgen in den Modulen selber und ich habe nichts privates bis auf die Tabelle im ersten Handlungsziel gemacht. Nichtsdestotrotz denke ich, ich habe das Meiste abgedeckt.
