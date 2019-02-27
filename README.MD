Web Shell Scoring
=================

![This script was last tested in Nuix 7.8](https://img.shields.io/badge/Script%20Tested%20in%20Nuix-7.8-green.svg)

View the GitHub project [here](https://github.com/Nuix/Web-Shell-Scoring) or download the latest release [here](https://github.com/Nuix/Web-Shell-Scoring/releases).

# Overview

This project looks to identify and score potential Web Shells.  This is accomplished using a Worker Side Script.  When an item's content text matches 1 or more regular expressions, this Worker Side Script assigns a score based on the sum of the regular expressions matched.

| Regular Expression | Score |
|--------------------|-------|
| `Copyright \(c\) 1997-2010 The PHP Group` | -200 |
| `eval\(` | 25 |
| `base64_decode\(` | 25 |
| `gzinflate` | 25 |
| `passthru\(` | 25 |
| `proc_open\(` | 25 |
| `system\(` | 25 |
| `shell_exec\(` | 25 |
| `cfexecute` | 25 |
| `cmd.exe` | 25 |
| `runcommand` | 25 |
| `mdEncode` | 25 |
| `zaco` | 25 |
| `zippo` | 25 |
| `XiX_` | 25 |
| `Nuke Shell` | 25 |
| `Reverse Shell` | 25 |
| `cleanCC\(` | 25 |
| `r57sh` | 25 |
| `c99sh` | 25 |
| `uZE Shell` | 25 |
| `TC9A16C47DA8EEE87` | 50 |
| `webshell` | 25 |
| `Nickserv.*identify` | 50 |
| `laudanum` | 50 |
| `web shell` | 25 |
| `0rb` | 25 |
| `orb` | 25 |
| `SQL Dumper` | 100 |
| `\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65` | 100 |
| `\\x65\\x76\\x61\\x6C` | 100 |
| `\\x28\\x62\\x61\\x73\\x65\\x36` | 100 |

The script only performs this test on item's where the mime type matches the regular expressions `script` or `text`.  As of Nuix 7.8.0.10 possible mime types matched by this are:

- `application/x-executable-script`
- `application/postscript`
- `application/vnd.google-apps.script`
- `application/vnd.vmware.vmdk-descriptor`
- `application/vnd.bloomberg-text-dump`
- `text/rtf`
- `text/x-vcalendar`
- `text/calendar-entry`
- `text/x-structured-text`
- `text/x-nuix-log`
- `text/x-inf`
- `text/plain`
- `text/x-ini`
- `text/csv`
- `application/vnd.oasis.opendocument.text`
- `application/vnd.uof.text`
- `text/x-log-entry`
- `text/x-common-log-entry`
- `text/tab-separated-values`
- `text/vcard-contact`
- `text/x-common-log`
- `text/html`
- `text/x-windows-registry`
- `text/calendar`
- `text/vcard`

The resulting score is then recorded as a custom metadata field named `WebShell Score` against the item.

# Getting Started

## Setup

Begin by downloading the latest release of this project.  Copy the files [Find Possible Web Shell.xml](https://github.com/Nuix/Web-Shell-Scoring/blob/master/Project/Find%20Possible%20Web%20Shell.xml) and [Find Probable Web Shell.xml](https://github.com/Nuix/Web-Shell-Scoring/blob/master/Project/Find%20Probable%20Web%20Shell.xml) to your saved searches directory.  On a Windows machine this will likely be either of the following:

- `%appdata%\Nuix\Saved Searches` - User level directory
- `%programdata%\Nuix\Saved Searches` - System level directory

**Warning!** Placing a saved search in a global directory makes it accessible to all Nuix users, however, it also potentially makes it editable by all users.  If a change is made by a single user to a saved search that generates an error, that error can impact all users on the system. 

Once the saved searches are dropped into the Nuix Saved Searches directory, they appear on the Go tab under Load Search as **Find Possible Web Shell** and **Find Probable Web Shell**. 

## Processing Data

1. In Nuix Workstation, create a new case and specify your evidence.
2. Open the **Evidence Processing Settings** dialog.
3. On the **Evidence Processing Settings** dialog under **Family Text Settings**, ensure that the check box for **Hide immaterial items (text rolled up to parent)** is not selected.
4. Under **Item Content Settings**, ensure that the check boxes for **Extract named entities from text** is selected.
5. On the **Evidence Processing Settings** dialog, click the **Worker Script** tab.
6. Select the **ruby** radio button and paste the contents of [WSS_WebShell_Scoring.rb](https://github.com/Nuix/Web-Shell-Scoring/blob/master/Project/WSS_WebShell_Scoring.rb) into the text field.
7. Click **OK** and finish ingesting the evidence you have specified.

## Reviewing the Results

After ingestion has completed, run the saved search **Find Possible Web Shell** or **Find Probable Web Shell**.

![image](https://user-images.githubusercontent.com/11775738/53528820-91182300-3a9f-11e9-921a-e5724d504252.png)

Use **Find Probable Web Shell** first to locate high confidence items.  Use **Find Probable Web Shell** to locate lower confidence items.

# License

```
Copyright 2019 Nuix

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```