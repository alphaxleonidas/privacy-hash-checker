# privacy-hash-checker
Check the filehash in VirusTotal database. Firefox + Chrome extension. **NO FILE UPLOAD**






<p float="left">
  <img
    src="https://addons.mozilla.org/user-media/previews/thumbs/372/372080.jpg?modified=1778611330"
    height="700"
  />
  <img
    src="https://addons.mozilla.org/user-media/previews/thumbs/372/372081.jpg?modified=1778611330"
    height="150"
  />
</p>


# For local installation: 

## Firefox:

- Download the xpi version from the [releases](https://github.com/alphaxleonidas/privacy-hash-checker/releases).

- Go to `about:addons` in your browser URL.

- Click on the gear icon <img width="25" height="25" alt="image" src="https://github.com/user-attachments/assets/ca42ecea-0f72-48e5-b96a-0010135f8f63" />  and choose ` Install Add-on from file`.

- Select the xpi file. 

- The extension should work permanently. 

## Chromium:

- Clone the Chromium branch of repo:

```
git clone https://www.github.com/alphaxleonidas/privacy-hash-checker.git -b chromium
```

  OR 
  
  Download the Chromium version from the [releases](https://github.com/alphaxleonidas/privacy-hash-checker/releases) and Extract it.

- Open your Chromium based browser, and enter this in the URL bar: `chrome://extensions`

- Toggle `Developer Mode` on the top right.

- Click `Load unpacked`  and select the whole folder contaning all the extension files. 

- It should work permanently.


# Link Scanning as a Search Engine

  To scan a link via search bar, add this to your browser's search engine in browser settings:

  ```
https://www.virustotal.com/gui/search?query=%s
```
Now you can scan the link using virustotal as a search engine. 

# Rough Work

[test](https://www.github.com/alphaxleonidas)
