# Contributing to Agent Paladin

Contributions are welcome. Please keep changes focused and include a clear
description of the security impact.

## License of contributions

By submitting a contribution, you agree that it is licensed to the project
under the Apache License, Version 2.0, unless you explicitly mark it as
"Not a Contribution" in writing. This is the default inbound-license rule in
Section 5 of the Apache-2.0 license.

## Developer Certificate of Origin

Sign off every commit with the Developer Certificate of Origin (DCO):

```sh
git commit -s
```

The sign-off certifies that you wrote the contribution, or have the right to
submit it under the project's license. See
<https://developercertificate.org/> for the full text.

## Third-party code

Do not submit code, images, fonts, model weights, or other material that you do
not have the right to license. If you include third-party material, add its
license and attribution to `THIRD_PARTY_NOTICES.md` and make sure it is
compatible with Apache-2.0.

In particular, do not add GPL-2.0-only code to the Apache-2.0 source tree.
GPL components may be used as separate containers or processes, as the existing
Squid-based egress image does, but they must not be relicensed or merged into
the Apache-2.0 code.

## AI-assisted contributions

AI tools are allowed, but you are responsible for the result. Review generated
code, check that it does not reproduce incompatible third-party code, and
ensure you have the right to submit it. If a change is substantially
AI-generated, say so in the pull request description.

## Security issues

Do not open a public issue for an undisclosed vulnerability. Follow
`SECURITY.md`.

## Before opening a pull request

* Run `make compile` and the relevant tests/checks.
* Run `./bin/scan` if your change touches secrets, configuration, or paths.
* Update documentation and `THIRD_PARTY_NOTICES.md` if you add a dependency or
  asset.
* Keep the change focused; separate refactors from behavior changes.
