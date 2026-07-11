# privacy-hash-checker
Check the filehash in VirusTotal database. Firefox + Chrome extension. **NO FILE UPLOAD**

# For local installation: 

## Firefox:

Download the xpi or zip version from the [releases](https://github.com/alphaxleonidas/privacy-hash-checker/releases).

Go to `about:addons` in your browser URL.

Click on the gear icon <img width="39" height="36" alt="image" src="https://github.com/user-attachments/assets/ca42ecea-0f72-48e5-b96a-0010135f8f63" />  and choose ` Install Add-on from file`.

Select the xpi or zip file. 

The extension should work permanently. 

## Chromium:

Clone the Chromium branch of repo:

```
git clone https://www.github.com/alphaxleonidas/privacy-hash-checker.git -b chromium
```

OR 

Download the Chromium version from the [releases](https://github.com/alphaxleonidas/privacy-hash-checker/releases) and Extract it.

Open your Chromium based browser, and enter this in the URL bar: `chrome://extensions`

Toggle `Developer Mode` on the top right.

Click `Load unpacked`  and select the whole folder contaning all the extension files. 

If you downloaded the zip file: 

It should work permanently.


# Link Scanning as a Search Engine

  To scan a link via virustotal on the search bar, add this to the list of search engine to your browser: (if on pc, you can create a keyword/shortcut e.g. "v") 

  ```
https://www.virustotal.com/gui/search?query=%s
```
Now you can scan the link using virustotal as a search engine. 

# Rough Work

[test](https://www.github.com/alphaxleonidas)
