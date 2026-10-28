# Security

wellhead is alpha software. Only the latest release is supported.

## Report a vulnerability

Report it privately through GitHub:
[open a draft security advisory](https://github.com/wellhead-dev/wellhead/security/advisories/new).
Do not put credentials, exploit details or private deployment data in a public issue or pull request.

A [maintainer](MAINTAINERS.md) aims to acknowledge a report within seven days, agree on severity with
you, fix it, and publish an advisory with credit once a fixed release is out. These are targets, not
guarantees, while the project has one maintainer.

## What wellhead handles

`wellhead seed` holds secret values in memory for the length of one command. It reads them from a
terminal without echo, from a file named as `FIELD=@FILE`, or from stdin when stdin is not a terminal;
never from its arguments. It sends them only in request bodies over TLS: to the vault, and to the
issuer a configured check calls (`https://` only). It never prints a value, and masks known values in
error messages. `wellhead missing --verify` reads values to check them and prints none.

The admission policy reads only annotations and the spec of ExternalSecrets, never values.

Releases are signed keylessly; [releasing](docs/releasing.md) shows how to verify a download.
