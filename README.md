# Private Access Tokens

Based on the ietf draft of [PrivacyPass](https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-05.html):

* [A PrivateAccess auth scheme generator](https://private-access-token.colinbendell.dev) to produce a valid challenge token
* [A PAT test site](https://private-access-token.colinbendell.dev/test.html) that only emits `WWW-Authenticate: PrivateAccess` auth schemes to test the flow on Safari16.

Currently PATs are only supported in Safari16 and use the [Private Access auth scheme](https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-05.html). However there are a few important details for Safari16:

* the `origin_info` parameter is optional but when provided must match the `Host:` header (not the servername= field in the TLS negotiation)
* the `challenge` and `token-key` fields are [base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5) encoded BUT padding (=) [is required](https://github.com/ietf-wg-privacypass/base-drafts/issues/117)
* The `token-key` from Fastly isn't accessible by accessing `/.well-known/token-issuer-directory`. A public key is available on their [blog post](https://www.fastly.com/blog/private-access-tokens-stepping-into-the-privacy-respecting-captcha-less) but is subject to change.
* all fields (`challenge`, `token-key` and `token`) need to be quoted if `=` padding is present
* However, macOS13 and iOS16 do not support "quoted" fields and there is no way to disambiguate a future version that might support properly quoted fields from the current OS releases :(
* [Cloudflare](https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/) is making the `token-issuer-directory` publicly accessible because it appears they are rotating their keys (at the time of writing they are on v16)
* There isn't a way to distinguish Safari 16 on an older version of macOS or iOS vs Safari 16 on macOS13 or iOS16 which do support PAT
* Challenges are rate limited to 1/60s for an established TLS socket. There appears to be other rate limits
* Safari16 doesn't support RSARSS-PSS oid with parameters in WebCrypto so you can't use the browser to validate.
  * You can, however, hack the base64 and convert it to a simple rsaEncoded RSARSS-PSS by taking the last 367 and prepending with "MIIBIjANBgkqhkiG9w0BAQEFA" to get a compatible oid
* On macOS a convenient way to watch token redemption: `log stream --predicate 'subsystem contains "networkserviceproxy"' --debug --info --style compact`

More details:
* [Apple's Private Access Token Dev announcement](https://developer.apple.com/news/?id=huqjyh7k)
