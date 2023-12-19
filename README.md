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

Das Artefakt ist mir gut gelungen, wir hatten es 1 zu 1 so im Unterricht angeschaut, weswegen es keine grosse Herausforderung dargestellt hat. Das Artefakt ist ein gutes Beispiel für einen unsicheren und sicheren code, wobei man sagen muss, man kann einen Code so gut wie immer noch sicherer gestalten.

## **_Handlungsziel 3_**



## **_Handlungsziel 4_**



## **_Handlungsziel 5_**



## Selbsteinschätzung des Erreichungsgrades der Kompetenz des Moduls
Geben Sie eine Selbsteinschätzung zu der Kompetenz in diesem Modul ab. Schätzen Sie selbst ein, inwiefern Sie die Kompetenz dieses Moduls erreicht haben und inwiefern nicht. Es geht in diesem Abschnitt nicht darum, auf die einzelnen Handlungsziele einzugehen. Das haben Sie bereits gemacht. Begründen Sie ihre Aussagen.
