const puppeteer = require('puppeteer');
const https = require('https');
const http2 = require('http2');
const fs = require('fs').promises;

async function getCloudflarePublicKey() {
    const browser = await puppeteer.launch({
        args: ['--no-sandbox'],
        executablePath: process.env.PUPPETEER_EXEC_PATH, // set by docker container
        headless: true
    });

    let key;
    let url;
    const page = await browser.newPage();
    page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1')
    page.on('response', res => {
        const headers = res.headers();
        if (headers['www-authenticate']?.match(/PrivateToken/)) {
            key = headers['www-authenticate'].split(/token-key=/)[1]?.split(/,/)[0];
            url = res.url();
        }
    });
    const go = await page.goto('https://private-access-token.colinbendell.dev/recaptcha.html', {waitUntil: 'networkidle0'});
    await browser.close()

    if (key) {
        console.log(url, key);
        await fs.writeFile(__dirname + '/../pat-issuer.cloudflare.com.txt', key, {encoding: 'utf8'});
    }
    return key;
}

async function getFastlyDemoPublicKey() {
    const url = 'https://patdemo-o.edgecompute.app/';

    const headers = await new Promise((resolve, reject) => {
        const client = http2.connect('https://patdemo-o.edgecompute.app');
        const req = client.request({
          ':method': 'POST',
          ':path': '/',
          'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
          'accept-language': 'en-US,en;q=0.9,pl;q=0.8',
          'content-type': 'application/x-www-form-urlencoded',
          'origin': 'https://patdemo-o.edgecompute.app',
          'referer': 'https://patdemo-o.edgecompute.app/?session=79787',
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
    if (headers['www-authenticate']?.match(/PrivateToken/)) {
        key = headers['www-authenticate'].split(/token-key=/)[1]?.split(/,/)[0];
    }

    if (key) {
        console.log(url, key);
        await fs.writeFile(__dirname + '/../demo-issuer.private-access-tokens.fastly.com.txt', key, {encoding: 'utf8'});
    }
    return key;
}

async function getCloudflareDemoPublicKey() {
    let url = "https://demo-pat.issuer.cloudflare.com/"
    let key;
    const body = await new Promise((resolve, reject) => {
        https.get('https://demo-pat.issuer.cloudflare.com/.well-known/token-issuer-directory', (res) => {
        res.setEncoding('utf8');
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve(body));
        }).end()
    });

    const json = JSON.parse(body);
    const keys = json["token-keys"];
    if (keys && keys.length > 0) {
      key = keys[0]["token-key"];
    }
    if (key) {
        console.log(url, key);
        await fs.writeFile(__dirname + '/../demo-pat.issuer.cloudflare.com.txt', key, {encoding: 'utf8'});
    }

    return key;
}

async function build() {
    const cfProdKey = await getCloudflarePublicKey();
    const cfDemoKey = await getCloudflareDemoPublicKey();
    const fastlyDemoKey = await getFastlyDemoPublicKey();

    for(const file of ['index.html', 'debug.html', 'test.html', 'worker/index.js']) {
        const path = __dirname + '/../' + file;
        let content = await fs.readFile(path, {encoding: 'utf8'});
        if (cfProdKey) content = content.replaceAll(/CLOUDFLARE_PUB_KEY = .*;/g, `CLOUDFLARE_PUB_KEY = "${cfProdKey}";`);
        if (cfDemoKey) content = content.replaceAll(/CLOUDFLARE_DEMO_PUB_KEY = .*;/g, `CLOUDFLARE_DEMO_PUB_KEY = "${cfDemoKey}";`);
        if (fastlyDemoKey) content = content.replaceAll(/FASTLY_PUB_KEY = .*;/g, `FASTLY_PUB_KEY = "${fastlyDemoKey}";`);
        await fs.writeFile(path, content, {encoding: 'utf8'});
    }
}
build();
