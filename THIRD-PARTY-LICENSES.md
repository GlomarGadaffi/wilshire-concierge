# Third-Party Licenses

GloSSH is MIT-licensed (see [LICENSE](LICENSE)). It vendors the following
third-party source, each under permissive or public-domain terms. The full
upstream license text is retained inside each vendored tree.

| Component | Version | License | Upstream | In-tree license file |
|-----------|---------|---------|----------|----------------------|
| Dropbear SSH | 2020.81 | MIT-style | https://github.com/mkj/dropbear | `components/dropbear/dropbear/LICENSE` |
| LibTomCrypt | bundled w/ dropbear | Public domain | https://github.com/libtom/libtomcrypt | `components/dropbear/dropbear/libtomcrypt/LICENSE` |
| LibTomMath | bundled w/ dropbear | Public domain | https://github.com/libtom/libtommath | `components/dropbear/dropbear/libtommath/LICENSE` |
| TinySSH | vendored | Public domain (CC0 fallback) | https://github.com/janmojzis/tinyssh | `components/tinyssh/tinyssh/LICENCE` |

None of the above are copyleft. There is no GPL, LGPL, or commercial-license
obligation anywhere in this tree.

## Provenance note

These trees were vendored flat (copied source, no submodules) from a working
ESP-IDF port. They may contain local ESP-IDF compatibility edits relative to
pristine upstream. To resync with upstream security patches, diff against the
tagged upstream releases listed above.
