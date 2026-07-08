# privacy-hash-checker
Check the filehash in VirusTotal database. Firefox + Chrome extension. ** NO FILE UPLOAD **

# For local installation: 

## Firefox:

Clone the repo 
```
 git clone https://www.github.com/alphaxleonidas/privacy-hash-checker.git
```
Open Firefox, and enter this in the URL bar: `about:debugging#/runtime/this-firefox`

Click `Load temporary Add-on`

Then navigate to the downloaded repo and select `manifest.json` from it.

It should work **temporarily**.

## Chromium:

Clone the Chromium branch of repo:

```
git clone https://www.github.com/alphaxleonidas/privacy-hash-checker.git -b chromium
```
Open your Chromium based browser, and enter this in the URL bar: `chrome://extensions`

Toggle `Developer Mode` on the top right.

Click `Load unpacked` and select the whole folder contaning all the extension files. 

It should work permanently.


# Link Scanning as a Search Engine

  To scan a link via virustotal on the search bar, add this to the list of search engine to your browser: (if on pc, you can create a keyword/shortcut e.g. "v") 

  ```
https://www.virustotal.com/gui/search?query=%s
```
Now you can scan the link using virustotal as a search engine. 

# Rough Work

[hidden](https://www.virustotal.com/gui/search?query=https%3A%2F%2Fhttps://www.deviantart.com%2Fmaciedevis%2Fcommission%2FFULL-BODY-1713765)

[test](https://www.github.com/alphaxleonidas)
