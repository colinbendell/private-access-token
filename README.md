# Private Access Tokens

Based on the ietf draft of [PrivacyPass](https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-05.html):

* [A PrivateAccess auth scheme generator](https://private-access-token.colinbendell.dev) to produce a valid challenge token
* [A PAT demo site](https://private-access-token.colinbendell.dev/test.html) that only emits `WWW-Authenticate: PrivateAccess` auth schemes to test the flow on Safari16.

Currently PATs are only supported in Safari16 and use the [Private Access auth scheme](https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-05.html). However there are a few important details for Safari 16:

* the `origin_info` parameter is required
* the `challenge` and `token-key` fields are [base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5) encoded BUT padding (=) [is required](https://github.com/ietf-wg-privacypass/base-drafts/issues/117)
* The `token-key` from Fastly isn't accessible by accessing `/.well-known/token-issuer-directory`. A public key is available on their [blog post](https://www.fastly.com/blog/private-access-tokens-stepping-into-the-privacy-respecting-captcha-less) but is subject to change.
* [Cloudflare](https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/) is making the `token-issuer-directory` publicly accessible because it appears they are rotating their keys (at the time of writing they are on v15)

More details:
* [Apple's Private Access Token Dev announcement](https://developer.apple.com/news/?id=huqjyh7k)
