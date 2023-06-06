import { launch } from 'puppeteer';
import { get } from 'https';
import { connect } from 'http2';
import { promises as fs } from 'fs';
import * as url from 'url';

import * as crypto from 'node:crypto';

const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

import { Base64, PS384 } from '../src/utils.js';
import { Challenge } from '../src/private-access-token.js';

async function sha256(data = []) {
    if (Array.isArray(data)) {
        data = new Uint8Array(data);
    }
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)));
}

function privateTokenToIssuerDirectory(authenticate = "") {
    if (!authenticate?.match(/PrivateToken/)) return;

    const key = authenticate?.split(/token-key=/)[1]?.split(/,/)[0];
    const challenge = Challenge.from(authenticate?.split(/challenge=/)[1]?.split(/,/)[0]);

    if (key) {
        const issuerDirectory = {
            "issuer-name": challenge.issuerName,
            "token-keys": [
                {
                    "token-type": 2,
                    "token-key": key,
                }
            ]};
        return issuerDirectory;
    }
}

async function getCloudflarePublicKey() {

    try {
        let headers;
        const browser = await launch({
            args: ['--no-sandbox'],
            executablePath: process.env.PUPPETEER_EXEC_PATH, // set by docker container
            headless: "true"
        });

        const page = await browser.newPage();
        page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1')
        page.on('response', res => {
            const resHeaders = res.headers();
            if (resHeaders['www-authenticate']?.match(/PrivateToken/)) {
                headers = resHeaders;
            }
        });
        await page.goto('https://private-access-token.colinbendell.dev/recaptcha.html', {waitUntil: 'networkidle0'});
        await browser.close()

        return privateTokenToIssuerDirectory(headers?.['www-authenticate']);
    }
    catch (e) {
        console.log(e);
    }
}

async function getFastlyDemoPublicKey() {
    try {
        const headers = await new Promise((resolve, reject) => {
            const client = connect('https://patdemo-o.edgecompute.app');
            const req = client.request({
            ':method': 'POST',
            ':path': '/',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9,pl;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://patdemo-o.edgecompute.app',
            'referer': 'https://patdemo-o.edgecompute.app/',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'
            });

            req.on('response', (headers) => {
                resolve(headers);
                client.destroy();
            });

            req.on('error', (error) => {
                reject(error);
                client.destroy();
            });
            req.on('close', () => {
                client.destroy();
            });
            // client.on('close', () => {
                // console.log('All client sockets have been destroyed');
            // });

            req.end();
        });

        return privateTokenToIssuerDirectory(headers?.['www-authenticate']);
    }
    catch (e) {
        console.log(e);
    }

}

async function getCloudflareDemoPublicKey() {
    let issuer = "demo-pat.issuer.cloudflare.com"
    let key;
    const body = await new Promise((resolve, reject) => {
        get('https://demo-pat.issuer.cloudflare.com/.well-known/token-issuer-directory', (res) => {
        res.setEncoding('utf8');
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve(body));
        }).end()
    });

    const issuerDirectory = JSON.parse(body);
    // const keys = issuerDirectory["token-keys"]
    //     ?.filter(k => new Date(k["not-before"] * 1000 || 0) < new Date())
    //     ?.sort((a, b) => b.version - a.version) || [];

    // key = keys[0]?.["token-key"];
    // if (key) {
    //     console.log(issuer, key);
    //     await fs.writeFile(__dirname + `/../${issuer}.txt`, key, {encoding: 'utf8'});
    // }
    issuerDirectory["issuer-name"] = issuer;

    return issuerDirectory;
}

async function build() {
    let issuers = await Promise.all([
        getCloudflarePublicKey(),
        getCloudflareDemoPublicKey(),
        getFastlyDemoPublicKey()
    ]);

    issuers = issuers.filter(i => i?.["token-keys"].length > 0);

    const issuerSet = new Set(issuers.map(i => i["issuer-name"]));

    const jwkIssuers = [];
    for (const directory of issuers) {
        const jwks = {
            "issuer": directory["issuer-name"],
            "keys": await Promise.all(
                directory["token-keys"]
                ?.map(key => PS384.toJWK(key["token-key"], {nbf: key["not-before"]}, sha256))) || [],
        };
        await fs.writeFile(__dirname + `/../${directory["issuer-name"]}.jwks.json`, JSON.stringify(jwks, null, 2), {encoding: 'utf8'});
        await fs.writeFile(__dirname + `/../${directory["issuer-name"]}.json`, JSON.stringify(directory, null, 2), {encoding: 'utf8'});

        jwkIssuers.push(...jwks.keys.map(k => Object.assign(k, {iss: directory["issuer-name"]})));
    }

    const jwkPath = __dirname + '/../PRIVATE_ACCESS_TOKEN.jwks.json';

    // back fill missing just in case an error happened
    const prevIssuers = JSON.parse(await fs.readFile(jwkPath, {encoding: 'utf8'}).catch(() => '{}')) || {};
    for (const jwk of prevIssuers?.keys || []) {
        if (!issuerSet.has(jwk.iss)) {
            jwkIssuers.push(jwk);
        }
    }

    const jwks = {
        keys: jwkIssuers
    }
    await fs.writeFile(jwkPath, JSON.stringify(jwks, null, 2), {encoding: 'utf8'});

    const path = __dirname + '/../PRIVATE_ACCESS_TOKEN_ISSUERS.json';
    issuers = jwkIssuers.map(i => (
        {
            "issuer-name": i.iss,
            "token-type": 2,
            "token-key": Base64.urlEncode(PS384.toASN(i)),
            "token-key-id": Base64.urlEncode(Base64.decode(i["x5t#S256"])),
        }
    ));

    const issuerDirectory = {
        "token-keys": issuers,
    }
    await fs.writeFile(path, JSON.stringify(issuerDirectory, null, 2), {encoding: 'utf8'});

    const cfProdKey = issuers.find(i => i.issuer === 'pat-issuer.cloudflare.com')?.["token-key"];
    const cfProdKeyID = issuers.find(i => i.issuer === 'pat-issuer.cloudflare.com')?.["token-key-id"];
    const cfDemoKey = issuers.find(i => i.issuer === 'demo-pat.issuer.cloudflare.com')?.["token-key"];
    const cfDemoKeyID = issuers.find(i => i.issuer === 'demo-pat.issuer.cloudflare.com')?.["token-key-id"];
    const fastlyDemoKey = issuers.find(i => i.issuer === 'demo-issuer.private-access-tokens.fastly.com')?.["token-key"];
    const fastlyDemoKeyID = issuers.find(i => i.issuer === 'demo-issuer.private-access-tokens.fastly.com')?.["token-key-id"];

    for(const file of ['src/private-access-token.js', 'private-access-token.colinbendell.dev/worker/index.js']) {
        const path = __dirname + '/../' + file;
        let content = await fs.readFile(path, {encoding: 'utf8'});
        if (cfProdKey) content = content.replaceAll(/CLOUDFLARE_PUB_KEY = .*;/g, `CLOUDFLARE_PUB_KEY = "${cfProdKey}";`);
        if (cfProdKey) content = content.replaceAll(/CLOUDFLARE_PUB_KEY_ID = .*;/g, `CLOUDFLARE_PUB_KEY_ID = "${cfProdKeyID}";`);
        if (cfDemoKey) content = content.replaceAll(/CLOUDFLARE_DEMO_PUB_KEY = .*;/g, `CLOUDFLARE_DEMO_PUB_KEY = "${cfDemoKey}";`);
        if (cfDemoKey) content = content.replaceAll(/CLOUDFLARE_DEMO_PUB_KEY_ID = .*;/g, `CLOUDFLARE_DEMO_PUB_KEY_ID = "${cfDemoKeyID}";`);
        if (fastlyDemoKey) content = content.replaceAll(/FASTLY_PUB_KEY = .*;/g, `FASTLY_PUB_KEY = "${fastlyDemoKey}";`);
        if (fastlyDemoKeyID) content = content.replaceAll(/FASTLY_PUB_KEY_ID = .*;/g, `FASTLY_PUB_KEY_ID = "${fastlyDemoKeyID}";`);
        await fs.writeFile(path, content, {encoding: 'utf8'});
    }
}
build();
