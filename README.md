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

## _Handlungsziel 1_

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

### Kritische Beurteilung der Umsetzung des Artefakts
Mein Artefakt sieht strukturiert und einfach zu lesen aus. Jedoch ist sie einbisschen kurz. Ich hätte anstatt die Top 3 Bedrohungen einfach alle Bedrohungen auflisten können. Wenn man die knappheit auslässt, finde ich, das Artefakt ist gut gelungen. Die Daten der owasp Webseite sind vertraulich.
## **_Handlungsziel 2_**

Aufträge bearbeitet: 
SQL_INjection
XSS
Unsaubere API
Review 
Pentests

code sql injection:
```csharp
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

    return Ok(CreateToken(user));
}
```
broken access controll:

```csharp
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

unsaubere API:

Hier mussten wir die Website an sich ändern. 

## **_Handlungsziel 3_**

BrokenAccessControl
Autorisierung
Authentifizierung
PasswortHashing

## **_Handlungsziel 4_**

SecretImRepository
HumanFactor
DefensiveProgrammierung

## **_Handlungsziel 5_**

Logging
Zusätzliche Lern-Arbeitsaufträge:
AuditTrail

## Selbsteinschätzung des Erreichungsgrades der Kompetenz des Moduls
Geben Sie eine Selbsteinschätzung zu der Kompetenz in diesem Modul ab. Schätzen Sie selbst ein, inwiefern Sie die Kompetenz dieses Moduls erreicht haben und inwiefern nicht. Es geht in diesem Abschnitt nicht darum, auf die einzelnen Handlungsziele einzugehen. Das haben Sie bereits gemacht. Begründen Sie ihre Aussagen.
