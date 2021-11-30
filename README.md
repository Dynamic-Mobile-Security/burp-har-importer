Плагин для импорта файлов в формате har (HTTP Archive format) в Burp (Target -> Sitemap).

За основу взят оригинальный плагин https://github.com/nccgroup/BurpImportSitemap/

## Import To Sitemap Extension

Import To Sitemap is a Burp Suite Extension to import wstalker CSV file or ZAP export file into Burp Sitemap. It also includes a contextual menu to send request/response items from any tab to the sitemap.



## В текущий плагин добавлено:
- возможность загрузки файлов в формате har.

## Особенности плагина:
- для сохранения разных HTTP-методов для одинакового URL используется флаг stingrayParamToExclude,
который добавляет этот параметр к URL и к нему уникальное значение uuid, тем самым URL становиться уникальным.
Этот костыль сделан из-за того, что Burp не может сохранить запрос с одинаковыми URL (он перезаписывается последним).
Если в архиве har нет "дублирующихся" URL, тогда можно флаг stingrayParamToExclude выключить.

## Сборка плагина:
> gradle -version
Gradle 6.4.1

> gradle buildFatJar

Собранный плагин будет в каталоге: build/libs/import-sitemap.jar



