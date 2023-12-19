# ZumsteinDavidLB-183

Sie arbeiten das Modul durch und weisen mit einem ePortfolio die erreichten Handlungsziele mit eigenen Beispielen von Artefakten (hergestellte Objekte / Produkte) nach. Sie weisen somit in dieser Leistungsbeurteilung nach, welche Handlungsziele Sie in welchem Masse erreicht haben. 

Sie erstellen zu den einzelnen Handlungszielen Artefakte (hergestellte Objekte / Produkte), anhand denen Sie beweisen können, dass Sie das Handlungsziel erreicht haben. Sie können dazu die abgegebene Applikation verwenden oder ‒ in Absprache mit der Lehrperson ‒ ein Beispiel aus Ihrer Firma oder aus dem Lernatelier. Anhand dieser Applikation weisen Sie mehrere oder sogar alle Handlungsziele nach.

Sie dürfen die selbst erarbeiteten Resultate der Aufträge im Modul als Artefakte übernehmen.


## Einleitung
Dies ist die Leistungsbeurteilung von David Zumstein. In diesem Portfolio zeige ich auf, wie ich jeweils ein Handlungsziel erfülle. Für jedes Handlungsziel wird erklärt um was es geht und anschliessend zeige ich mit einem Artefakt auf, wie ich das Handlungsziel erfüllt habe. Ingesamt sind es 5 Handlungsziele.

## Abschnitt pro Handlungsziel
Pro Handlungsziel ist ein Abschnitt mit folgendem Inhalt zu erstellen:

1. Wählen Sie ein Artefakt, welches Sie selbst erstellt haben und anhand dem Sie zeigen können, dass Sie das Handlungsziel erreicht haben.

2. Weisen Sie nach, wie Sie das Handlungsziel erreicht haben. Verweisen Sie dabei auf das von Ihnen erstellte Artefakt. Das Artefakt muss im ePortfolio sichtbar oder verlinkt sein.

3. Erklären Sie das Artefakt in wenigen Sätzen. Sollte das Artefakt mehrere Handlungsziele beinhalten dürfen Sie die Erklärung auch zusammenfassen.

4. Beurteilen Sie die Umsetzung Ihres Artefakts im Hinblick auf das Handlungsziel kritisch. Sollten gewisse Aspekte des Handlungsziels fehlen, haben Sie die Möglichkeit, in diesem Teil darauf einzugehen.

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
