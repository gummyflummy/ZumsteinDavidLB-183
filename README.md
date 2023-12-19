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

Im Ersten Handlungsziel haben wir die Infrastruktur eingerichtet und eine unsichere Beispielsapp heruntergeladen. Anschliessend haben wir im Plenum die App gestartet und den Aufbau einbisschen angeschaut. Als Anschluss haben wir über ein paar wichtigen Grundbegriffen recherchiert, wie Zum Beispiel ```integrität```, ```Vertraulichkeit``` und ```Verfügbarkeit```. Wir haben Situationen erhalten und mussten schätzen wie sehr die Begriffe auf das Szenario zutreffen.

Beim Auftrag ```LA_183_10_Business_Logic```, haben wir die REST-Endpoints zum Bearbeiten und löschen angeschaut. Es ist aufgefallen, dass wenn man die ID des News Eintrags kannte, dieser bearbeitet oder gelöscht werden kann. Der Benutzer wurde im Backend nicht geprüft. Als Reaktion darauf hatten wir die Aufgabe das Programm zu verändern, damit normale Benutzer nur noch ihre eigenen News bearbeiten und löschen konnten.

Artefakt:
Folgende Änderungen wurden im Code gemacht:

```csharp
//In NewsController.cs
public class NewsController : ControllerBase

//mehr Code...

[HttpPatch("{id}")]
[ProducesResponseType(200)]
/////////////////////////////
[ProducesResponseType(403)]
////////////////////////////
hinzugefüt
[ProducesResponseType(404)]

public ActionResult Update(int id, NewsWriteDto request)
{
  return NotFound(string.Format("News {0} not found", id));
}
///////////////////////////////////////////////////////////////////////////
if (!_userService.IsAdmin() && _userService.GetUserId() != news.AuthorId)
{
  return Forbid();
}
////////////////////////////////////////////////////////////////////////////
hinzugefügt

//noch mehr code...

[HttpDelete("{id}")]
[ProducesResponseType(200)]
/////////////////////////////
[ProducesResponseType(403)] 
/////////////////////////////
hinzugefügt
[ProducesResponseType(404)]

public ActionResult Delete(int id)
{
  return NotFound(string.Format("News {0} not found", id));
}

///////////////////////////////////////////////////////////////////////////
if (!_userService.IsAdmin() && _userService.GetUserId() != news.AuthorId)
{
  return Forbid();
}
///////////////////////////////////////////////////////////////////////////
hinzugefügt

```

Vor Änderung: (Screenshot zeigen): 
User konnte mit Adminrechte einen 'AdminNews' erstellen (und kann diese immer noch bearbeiten.)
jetzt kommt der Error 401 --> Screenshot zeigen vom Error und versuchen des erstellen des newbeitrags als 'admin'. 


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
