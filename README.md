Plugin for importing files in HAR format (HTTP archive) into Burp (Target -> Sitemap).

The original plugin is taken as a basis https://github.com/nccgroup/BurpImportSitemap/

## Import To Sitemap Extension

Import To Sitemap is a Burp Suite Extension to import wstalker CSV file or ZAP export file into Burp Sitemap. 
It also includes a contextual menu to send request/response items from any tab to the sitemap.



## Added to the plugin:
 - Ability to download files in HAR format.

## Plugin features:
- the `mdastParamToExclude` flag is used to save different HTTP methods for the same URL.
  This feature adds fake parameter with unique uuid value to the URL (to make the URL unique).
  This parameter is added to the URL only for the second and subsequent requests, the URL of the first request remains clean.
  This crutch is made because Burp cannot save a request with the same URL (it gets rewritten by the last one).
- If there are no "duplicate" URLs in the har archive, then the `mdastParamToExclude` flag can be turned off.

## Build instructions:
> gradle -version
Gradle 6.4.1

> gradle buildFatJar

The built plugin will be in the directory: `build/libs/import-sitemap.jar`