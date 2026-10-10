# Privacy policy

SailToken is an authenticator for two-factor login codes (TOTP) on
Sailfish OS. This policy describes what the app does with your data. It
applies to SailToken 0.5 and later.

## What SailToken collects

Nothing. SailToken has no analytics, no crash reporting, no advertising
and no account. It never sends data to the developer or to any third
party.

## Where your data is stored

- Your accounts are stored on your phone in one file, in SailToken's
  private app directory, which other sandboxed apps cannot read. The file
  is encrypted with your master password. A key file, if your file uses
  one, is stored next to it as it is.
- The app keeps the last three versions of the file as encrypted backups
  in the same directory.
- The settings file holds, if you set up sync, the time and file
  fingerprints (ETag and SHA-256) of the last sync and a fingerprint of
  the sync settings you confirmed. It holds no passwords, secrets or
  codes.
- When you save a copy, it goes to the folder you choose (Documents or
  Downloads), encrypted like the file.

## Camera

SailToken uses the camera only while a scan page is open, to read the
QR code a service shows when you turn on two-factor login, or the export
codes another authenticator app shows when you import its accounts. The
camera images are processed on the phone and never stored or sent
anywhere.

## Network access

SailToken connects to nothing but your own Nextcloud server, and only
after you set up sync. It then uploads and downloads your file,
encrypted, and nothing else. The address of the server, the user name and
the Nextcloud app password are stored inside your encrypted file. Your
Nextcloud provider's privacy policy applies to the data on that server.

To set up sync with the browser login, SailToken opens your Nextcloud's
login page in the Sailfish browser.

## Permissions

- **Camera:** only on the scan pages, to read QR codes.
- **Documents and Downloads:** to add an existing file and its key file,
  merge a copy, save a copy and read a backup of another authenticator
  app to import, always files that you pick or name. SailToken never
  deletes or changes such a backup; delete it yourself after the import.
- **Internet:** only for the Nextcloud sync you set up.

## Contact

Questions about privacy: open an issue at
https://github.com/tordenskjoldsw/harbour-sailtoken/issues. For security
reports, see [SECURITY.md](SECURITY.md).
