# privacy-hash-checker
Check the filehash in VirusTotal database. Firefox extension. ** NO FILE UPLOAD **

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

## Android [Firefox]

Clone the Android branch of repo:

```
git clone https://www.github.com/alphaxleonidas/privacy-hash-checker.git -b android
```
Or just download the .xpi from the releases section.

Open Firefox on Android. Open Settings > About Firefox. Click on the Firefox logo 5 times > Enables Debug menu. 

Go to a new tab. Open `about:config`. 

Search `xpinstall.signatures.required` and toggle it to false. 

Go to settings page. Scroll down to `Secret Settings`. Enable `Keep Debug Menu revealed`.

Go back to settings page. Scroll down and select `Install Extension from file`. Select `privacy-hash-checker-android.xpi`. 

Now the extension should work permanently.


# Rough Work

[hidden](https://www.virustotal.com/gui/search?query=https%3A%2F%2Fhttps://www.deviantart.com%2Fmaciedevis%2Fcommission%2FFULL-BODY-1713765)

[test](https://www.github.com/alphaxleonidas)
