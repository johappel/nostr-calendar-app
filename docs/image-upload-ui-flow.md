# Bild-Upload UI Flow

## Aktuelles UI-Layout

```
┌─────────────────────────────────────────────────────┐
│ Event-Formular                                      │
├─────────────────────────────────────────────────────┤
│                                                     │
│ Titel: [________________]                          │
│                                                     │
│ Beginn: [2025-10-01T10:00]  Ende: [2025-10-01T12:00]│
│                                                     │
│ Status: [Geplant ▼]                                │
│                                                     │
│ Ort: [_______________________________________]      │
│                                                     │
│ Bild-URL: [_________________________________]      │
│                                                     │
│  ┌──────────────┐  ┌─────────────┐               │
│  │ 📁 Mediathek │  │ 📤 Hochladen │               │
│  └──────────────┘  └─────────────┘               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Workflow-Diagramme

### Workflow 1: Aus Mediathek auswählen

```
┌──────────────┐
│ User klickt  │
│ "Mediathek"  │
└──────┬───────┘
       │
       v
┌──────────────────────────────────────────┐
│ Blossom Modal öffnet sich                │
│ ┌────────────────────────────────────┐   │
│ │ Filter: [Typ ▼] [Größe] [Datum]   │   │
│ └────────────────────────────────────┘   │
│ ┌────────────────────────────────────┐   │
│ │ Preview  │ Datei     │ Aktionen   │   │
│ ├──────────┼───────────┼────────────┤   │
│ │ [img]    │ foto.jpg  │ [Verwenden]│◄──┐
│ │ [img]    │ banner.png│ [Verwenden]│   │
│ │ [img]    │ logo.webp │ [Verwenden]│   │
│ └────────────────────────────────────┘   │
└──────────────────────────────────────────┘
       │
       │ User klickt "Verwenden"
       │
       v
┌──────────────────────────────────────┐
│ ✅ URL in f-image eingetragen        │
│ ✅ Modal schließt automatisch        │
│ ✅ Toast: "Bild als Event-Bild"      │
└──────────────────────────────────────┘
```

### Workflow 2: Neues Bild hochladen

```
┌──────────────┐
│ User klickt  │
│ "Hochladen"  │
└──────┬───────┘
       │
       v
┌──────────────────────────────────────┐
│ Dateiauswahl-Dialog öffnet sich      │
│                                      │
│  ┌─────────────────────────────┐    │
│  │  Dokumente                  │    │
│  │  ├─ foto1.jpg               │    │
│  │  ├─ foto2.png        [Öffnen]◄───┐
│  │  └─ screenshot.webp        │    │
│  └─────────────────────────────┘    │
└──────────────────────────────────────┘
       │
       │ User wählt Datei
       │
       v
┌──────────────────────────────────────┐
│ ℹ️ Bild wird hochgeladen...          │
└──────────────────────────────────────┘
       │
       │ Upload zu Blossom
       │
       v
┌──────────────────────────────────────┐
│ ✅ Bild erfolgreich hochgeladen!     │
│ ✅ URL in f-image eingetragen        │
└──────────────────────────────────────┘
```

### Workflow 3: Manuelle URL-Eingabe (unverändert)

```
┌──────────────────────────────────────┐
│ User gibt URL direkt ein:            │
│                                      │
│ Bild-URL: [https://example.com/i.jpg]│
│                                      │
│  ┌──────────────┐  ┌─────────────┐  │
│  │ 📁 Mediathek │  │ 📤 Hochladen │  │
│  └──────────────┘  └─────────────┘  │
│                                      │
└──────────────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ ✅ URL wird beim Speichern verwendet │
└──────────────────────────────────────┘
```

## Blossom Modal - Detailansicht

```
╔═══════════════════════════════════════════════════════════╗
║ Blossom Media                                      [✕]    ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║ Typ: [Bilder ▼]  Größe: [min____] [max____]  [← 1/5 →]  ║
║                                                           ║
║ ┌─────────────────────────────────────────────────────┐  ║
║ │ Dateien hier ablegen oder klicken zum Auswählen...  │  ║
║ └─────────────────────────────────────────────────────┘  ║
║                                                           ║
║ ┌───────────────────────────────────────────────────────┐║
║ │Preview │ Datei              │ Größe │ Datum │ Aktionen│║
║ ├────────┼────────────────────┼───────┼───────┼─────────┤║
║ │[🖼️]    │ event-banner.jpg   │ 245KB │ 01.10 │         │║
║ │        │ https://files...   │       │       │ ┌──────┐│║
║ │        │                    │       │       │ │Verwen│◄─┐
║ │        │                    │       │       │ │ den  ││ │
║ │        │                    │       │       │ └──────┘│ │
║ │        │                    │       │       │ [Copy]  │ │
║ │        │                    │       │       │ [Delete]│ │
║ ├────────┼────────────────────┼───────┼───────┼─────────┤║
║ │[🖼️]    │ logo.png           │ 89KB  │ 30.09 │         │║
║ │        │ https://files...   │       │       │ [Verwen]│║
║ │        │                    │       │       │ [Copy]  │║
║ │        │                    │       │       │ [Delete]│║
║ └────────┴────────────────────┴───────┴───────┴─────────┘║
║                                                           ║
║ [🔄 Liste aktualisieren]  📊 25 Dateien (gefiltert)      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
     │
     │ Nach Klick auf "Verwenden"
     │
     v
Zurück zum Event-Formular mit URL eingetragen
```

## State-Diagramm

```
                    ┌─────────────────┐
                    │ Event-Formular  │
                    │    geöffnet     │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              v              v              v
      ┌──────────┐   ┌──────────┐   ┌──────────┐
      │"Mediathek│   │"Hochladen│   │ Manuelle │
      │  Button" │   │  Button" │   │  Eingabe │
      └────┬─────┘   └────┬─────┘   └────┬─────┘
           │              │              │
           v              v              │
    ┌──────────┐   ┌──────────┐        │
    │ Blossom  │   │  Datei-  │        │
    │  Modal   │   │ Auswahl  │        │
    └────┬─────┘   └────┬─────┘        │
         │              │              │
         │              v              │
         │       ┌──────────┐         │
         │       │ Upload   │         │
         │       │to Blossom│         │
         │       └────┬─────┘         │
         │            │              │
         └────────────┼──────────────┘
                      │
                      v
              ┌────────────────┐
              │ URL in f-image │
              │   eingetragen  │
              └────────────────┘
```

## Komponenten-Beziehungen

```
┌─────────────────────────────────────────────────────┐
│ index.html                                          │
│ ┌─────────────────────────────────────────────────┐│
│ │ Event-Formular (modal)                          ││
│ │ ┌─────────────────────────────────────────────┐ ││
│ │ │ <input id="f-image" />                      │ ││
│ │ │ <button id="btn-select-from-blossom">       │ ││
│ │ │ <input id="f-image-file" style="hidden">    │ ││
│ │ │ <button id="btn-upload-image">              │ ││
│ │ └─────────────────────────────────────────────┘ ││
│ └─────────────────────────────────────────────────┘│
│                                                     │
│ ┌─────────────────────────────────────────────────┐│
│ │ Blossom Modal                                   ││
│ │ ┌─────────────────────────────────────────────┐ ││
│ │ │ <table id="blossom-table">                  │ ││
│ │ │   <button class="use-image">Verwenden      │ ││
│ │ │   <button class="copy">Copy                │ ││
│ │ │   <button class="del">Delete               │ ││
│ │ └─────────────────────────────────────────────┘ ││
│ └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
                        │
                        │ Event Listeners
                        │
                        v
┌─────────────────────────────────────────────────────┐
│ app.js                                              │
│ ┌─────────────────────────────────────────────────┐│
│ │ setupUpload()                                   ││
│ │   ├─ btnSelectFromBlossom.addEventListener()   ││
│ │   │    └─> Öffnet Blossom Modal                ││
│ │   │        └─> refreshBlossom()                ││
│ │   │            └─> renderBlossom()             ││
│ │   │                                            ││
│ │   └─ btnUploadImage.addEventListener()         ││
│ │        └─> fileInput.click()                   ││
│ │            └─> fileInput.addEventListener()    ││
│ │                └─> uploadToBlossom(file)       ││
│ │                    └─> f-image.value = url     ││
│ └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
                        │
                        │ Imports & Calls
                        │
                        v
┌─────────────────────────────────────────────────────┐
│ blossom.js                                          │
│ ┌─────────────────────────────────────────────────┐│
│ │ uploadToBlossom(file)                           ││
│ │   └─> Upload zu Blossom/NIP-96 Server          ││
│ │       └─> cacheUpload(data)                    ││
│ │           └─> localStorage.setItem()           ││
│ │                                                 ││
│ │ renderBlossom(table, ...)                       ││
│ │   └─> Zeigt Tabelle mit Bildern               ││
│ │       └─> "Verwenden"-Button Handler           ││
│ │           └─> f-image.value = url              ││
│ │               └─> blossomModal.close()         ││
│ │                                                 ││
│ │ refreshBlossom()                                ││
│ │   └─> listBlossom()                            ││
│ │       └─> getCachedUploads()                   ││
│ └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
```

## Datenfluss

### Upload Flow
```
User wählt Datei
        │
        v
File Object ──────> uploadToBlossom(file)
                            │
                            v
                    ┌───────┴───────┐
                    │               │
                    v               v
            Blossom PUT      NIP-96 POST
            (mit Auth)       (mit Auth)
                    │               │
                    └───────┬───────┘
                            │
                            v
                    Server Response
                    { url, meta }
                            │
                            v
                    cacheUpload({
                      url, size, type,
                      name, created, id
                    })
                            │
                            v
                    localStorage.setItem(
                      'blossom-uploads',
                      JSON.stringify([...])
                    )
                            │
                            v
                    Return { url }
                            │
                            v
            imageUrlInput.value = url
                            │
                            v
            showNotification(
              '✅ Erfolgreich!'
            )
```

### Select Flow
```
User klickt "Mediathek"
        │
        v
Blossom Modal öffnet
        │
        v
listBlossom()
        │
        v
getCachedUploads()
        │
        v
localStorage.getItem('blossom-uploads')
        │
        v
JSON.parse(cached)
        │
        v
renderBlossom(items)
        │
        v
┌─────────────────────────┐
│ For each image item:    │
│ ┌─────────────────────┐ │
│ │ Create table row    │ │
│ │ Add "Verwenden" btn │ │
│ │   onClick:          │ │
│ │     f-image.value   │ │
│ │     close modal     │ │
│ │     show toast      │ │
│ └─────────────────────┘ │
└─────────────────────────┘
        │
        v
User klickt "Verwenden"
        │
        v
imageUrlInput.value = url
        │
        v
blossomModal.close()
        │
        v
showNotification('✅ Gesetzt')
```

## Fehlerbehandlung

```
┌─────────────────────────────────────────┐
│ Upload-Versuch                          │
└────────┬────────────────────────────────┘
         │
         v
┌─────────────────────────────────────────┐
│ Validierung: Ist es ein Bild?           │
└────┬────────────────────────────────┬───┘
     │                                │
     │ Nein                          Ja
     │                                │
     v                                v
┌─────────────────┐         ┌─────────────────┐
│ showNotification│         │ uploadToBlossom │
│ ('Bitte Bild',  │         │                 │
│  'error')       │         └────────┬────────┘
└─────────────────┘                  │
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    v                v                v
            ┌────────────┐   ┌────────────┐   ┌────────────┐
            │ Blossom    │   │   NIP-96   │   │  Fallback  │
            │  Success   │   │  Success   │   │   Error    │
            └────┬───────┘   └────┬───────┘   └────┬───────┘
                 │                │                │
                 v                v                v
         ┌──────────────────────────────────────────────┐
         │ showNotification                             │
         │  Success: '✅ Erfolgreich hochgeladen!'      │
         │  Error:   '❌ Fehlgeschlagen: ${error}'      │
         └──────────────────────────────────────────────┘
```

## Tastatur-Navigation

```
Tab-Reihenfolge im Formular:
1. f-title
2. f-start
3. f-end
4. f-status
5. f-location
6. f-image (URL-Eingabefeld)
7. btn-select-from-blossom ◄── NEU
8. btn-upload-image        ◄── NEU
9. f-summary
10. ...

Enter auf Buttons:
- "Mediathek" → Modal öffnet
- "Hochladen" → File-Dialog öffnet

Escape:
- Schließt Blossom Modal
- Schließt Event Modal
```

## Responsive Verhalten

```
Desktop (> 768px):
┌────────────────────────────────────┐
│ Bild-URL: [__________________]     │
│ [📁 Mediathek] [📤 Hochladen]      │
└────────────────────────────────────┘

Mobile (< 768px):
┌────────────────────────────────────┐
│ Bild-URL: [__________________]     │
│ [📁 Mediathek]                     │
│ [📤 Hochladen]                     │
└────────────────────────────────────┘
```
