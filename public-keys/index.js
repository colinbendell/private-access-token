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

async function getCloudflarePublicKey() {
    const browser = await launch({
        args: ['--no-sandbox'],
        executablePath: process.env.PUPPETEER_EXEC_PATH, // set by docker container
        headless: "true"
    });

    let key;
    let issuer;
    const page = await browser.newPage();
    page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1')
    page.on('response', res => {
        const headers = res.headers();
        if (headers['www-authenticate']?.match(/PrivateToken/)) {
            const authenticate = headers['www-authenticate'];
            key = authenticate.split(/token-key=/)[1]?.split(/,/)[0];
            const challenge = Challenge.from(authenticate.split(/challenge=/)[1]?.split(/,/)[0]);
            issuer = challenge.issuerName;
        }
    });
    const go = await page.goto('https://private-access-token.colinbendell.dev/recaptcha.html', {waitUntil: 'networkidle0'});
    await browser.close()

    if (key) {
        console.log(issuer, key);
        await fs.writeFile(__dirname + `/../${issuer}.txt`, key, {encoding: 'utf8'});
    }
    return {issuer, key};
}

async function getFastlyDemoPublicKey() {
    const url = 'https://patdemo-o.edgecompute.app/';

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

    let key;
    let issuer;
    if (headers['www-authenticate']?.match(/PrivateToken/)) {
        const authenticate = headers['www-authenticate'];
        key = authenticate.split(/token-key=/)[1]?.split(/,/)[0];
        const challenge = Challenge.from(authenticate.split(/challenge=/)[1]?.split(/,/)[0]);
        issuer = challenge.issuerName;
    }

    if (key) {
        console.log(issuer, key);
        await fs.writeFile(__dirname + `/../${issuer}.txt`, key, {encoding: 'utf8'});
    }
    return {issuer, key};
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

    const json = JSON.parse(body);
    const keys = json["token-keys"]
        ?.filter(k => new Date(k["not-before"] * 1000 || 0) < new Date())
        ?.sort((a, b) => b.version - a.version) || [];

    key = keys[0]?.["token-key"];
    if (key) {
        console.log(issuer, key);
        await fs.writeFile(__dirname + `/../${issuer}.txt`, key, {encoding: 'utf8'});
    }

    return {issuer, key};
}

async function build() {
    let issuers = await Promise.all([
        getCloudflarePublicKey(),
        getCloudflareDemoPublicKey(),
        getFastlyDemoPublicKey()
    ]);

    const publicKeys = await Promise.all(
        issuers
            .filter(i => !!i.key)
            .map(async i => await PS384.toJWK(i.key, {issuer: i.issuer}, sha256))
    );

    const issuerSet = new Set();
    for (const issuer of publicKeys) {
        issuerSet.add(issuer.iss);
    }

    const path = __dirname + '/../PRIVATE_ACCESS_TOKEN_ISSUERS.json';
    const jwkPath = __dirname + '/../PRIVATE_ACCESS_TOKEN.jwks.json';

    // back fill missing just in case an error happened
    const prevIssuers = JSON.parse(await fs.readFile(jwkPath, {encoding: 'utf8'}).catch(() => '{}')) || {};
    for (const issuer of prevIssuers?.keys || []) {
        if (!issuerSet.has(issuer.iss)) {
            console.log(issuer.iss);
            publicKeys.push(issuer);
        }
    }

    issuers = publicKeys.map(i => ({ key: Base64.encode(PS384.toASN(i)), issuer: i.issuer, keyID: i.kid }));

    const jwks = {
        keys: publicKeys
    }
    await fs.writeFile(path, JSON.stringify(issuers, null, 2), {encoding: 'utf8'});
    await fs.writeFile(jwkPath, JSON.stringify(jwks, null, 2), {encoding: 'utf8'});

    const cfProdKey = issuers.find(i => i.issuer === 'pat-issuer.cloudflare.com')?.key;
    const cfProdKeyID = issuers.find(i => i.issuer === 'pat-issuer.cloudflare.com')?.keyID;
    const cfDemoKey = issuers.find(i => i.issuer === 'demo-pat.issuer.cloudflare.com')?.key;
    const cfDemoKeyID = issuers.find(i => i.issuer === 'demo-pat.issuer.cloudflare.com')?.keyID;
    const fastlyDemoKey = issuers.find(i => i.issuer === 'demo-issuer.private-access-tokens.fastly.com')?.key;
    const fastlyDemoKeyID = issuers.find(i => i.issuer === 'demo-issuer.private-access-tokens.fastly.com')?.keyID;

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
