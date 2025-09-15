# Nostr Calendar WordPress Plugin - Installation

## ✅ Installation erfolgreich!

Ihr WordPress Plugin ist jetzt installiert und kann verwendet werden.

## 🔄 Aktueller Status: Entwicklungsmodus

Das Plugin läuft aktuell im **Fallback-Modus** mit vereinfachter Kryptographie:
- ✅ Grundfunktionen verfügbar
- ✅ Event-Erstellung möglich  
- ✅ WordPress-Integration funktional
- ⚠️ Kryptographie vereinfacht (nur für Entwicklung/Demo)

## 🚀 Nächste Schritte

### 1. Plugin in WordPress aktivieren
```bash
# Plugin-Ordner nach WordPress kopieren
cp -r wordpress-plugin /path/to/wordpress/wp-content/plugins/nostr-calendar
```

### 2. WordPress Admin-Interface
1. Gehen Sie zu **WordPress Admin → Plugins**
2. Aktivieren Sie **"Nostr Calendar"**
3. Gehen Sie zu **Settings → Nostr Calendar**
4. Konfigurieren Sie Ihre Nostr-Relays

### 2.b SPA-Zugang bereitstellen

Das Plugin liefert optional eine Single-Page-App aus dem Plugin-Ordner unter der URL `https://example-wp.com/nostr-calendar` aus. Dazu legen Sie die gebaute `index.html` Ihrer Frontend-App in eines der folgenden Verzeichnisse:

- `wp-content/plugins/nostr-calendar/assets/index.html`

Nach dem Hochladen der Datei rufen Sie die URL `https://your-site/nostr-calendar` auf. Das Plugin registriert beim Aktivieren eine Rewrite-Rule und liefert die Datei direkt aus. Wenn Sie Probleme mit 404 haben, flushen Sie die Rewrite-Regeln in WordPress (Einstellungen → Permalinks → Änderungen speichern) oder führen Sie:

```bash
# Flush rewrite rules via WP-CLI
wp rewrite flush --allow-root
```


### 3. Shortcode verwenden
```php
// Vollständiger Kalender
[nostr_calendar theme="light" view="month"]

// Benutzer-spezifischer Kalender
[nostr_user_calendar readonly="true"]
```

## 🔒 Für Produktionsumgebung (optional)

Um echte secp256k1-Kryptographie zu aktivieren:

### 1. GMP Extension installieren
```bash
# Ubuntu/Debian
sudo apt-get install php-gmp

# CentOS/RHEL
sudo yum install php-gmp

# Windows (XAMPP)
# Uncomment extension=gmp in php.ini
```

### 2. Crypto-Libraries installieren
```bash
cd wordpress-plugin
composer require kornrunner/secp256k1
```

### 3. Status prüfen
Nach der Installation zeigt **Settings → Nostr Calendar** den Produktionsstatus an.

## 📋 Plugin-Features

### ✅ Verfügbare Funktionen:
- **WordPress SSO Integration** - Nutzt bestehende WP-Benutzer
- **Event-Erstellung** - Termine über WordPress-Interface
- **Nostr-Publishing** - Events werden zu Relays gesendet
- **Responsive UI** - Modernes Calendar-Interface
- **Admin-Interface** - Relay-Konfiguration
- **Shortcode-Support** - Einfache Integration in Seiten

### 🔧 API-Endpoints:
- `GET /wp-json/nostr-calendar/v1/me` - Benutzer-Status
- `POST /wp-json/nostr-calendar/v1/event` - Event erstellen
- `DELETE /wp-json/nostr-calendar/v1/event/{id}` - Event löschen
- `GET /wp-json/nostr-calendar/v1/sso-status` - SSO-Status


## 🐛 Troubleshooting

### Plugin nicht sichtbar?
- Prüfen Sie Dateiberechtigungen
- Kontrollieren Sie WordPress-Logs

### Crypto-Warnung?
- Normal im Entwicklungsmodus
- Für Produktion: ext-gmp installieren

### Events werden nicht publiziert?
- Prüfen Sie Relay-URLs in Settings
- Kontrollieren Sie Netzwerk-Verbindungen

## 📞 Support

- GitHub Issues: https://github.com/johappel/nostr-calendar-app/issues
- WordPress-Community: wp.org Support Forums

---

**Ihr Plugin ist einsatzbereit! 🎉**