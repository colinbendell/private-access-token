# Private Access Token Generator

A demo site to create Auth Challenge tokens for Private Access Tokens.

Currently PATs are only supported in Safari16 and use the [https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-05.html](Private Access auth scheme). However there are a few important details for Safari 16:

* the `origin_info` parameter is required
* the `challenge` and `token-key` fields are [https://datatracker.ietf.org/doc/html/rfc4648#section-5](base64url) encoded BUT padding (=) is required
* The `token-key` from Fastly isn't accessible by accessing `/.well-known/token-issuer-directory`. A public key is available on their [https://www.fastly.com/blog/private-access-tokens-stepping-into-the-privacy-respecting-captcha-less](blog post) but is subject to change.
* [https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/](Cloudflare) is making the `token-issuer-directory` publicly accessible because it appears they are rotating their keys (at the time of writing they are on v15)

More details:
* [https://developer.apple.com/news/?id=huqjyh7k](Apple's Private Access Token Dev announcement)