const puppeteer = require('puppeteer');
const https = require('https');
const fs = require('fs');

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
        fs.writeFileSync(__dirname + '/../pat-issuer.cloudflare.com.txt', key, 'utf8');
    }
    return key;
}

async function getCloudflareDemoPublicKey() {
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
        console.log(key);
        fs.writeFileSync(__dirname + '/../demo-pat.issuer.cloudflare.com.txt', key, 'utf8');
    }

    return key;
}

async function build() {
    const prodKey = await getCloudflarePublicKey();
    const demoKey = await getCloudflareDemoPublicKey();

    for(const file of ['index.html', 'worker/index.js']) {
        const path = __dirname + '/../' + file;
        const content = fs.readFileSync(path, 'utf8');
        const newContent = content
        .replace(/CLOUDFLARE_PUB_KEY = .*;/g, `CLOUDFLARE_PUB_KEY = "${prodKey}"`)
        .replace(/CLOUDFLARE_DEMO_PUB_KEY/g, `CLOUDFLARE_DEMO_PUB_KEY = "${demoKey}"`);
        fs.writeFileSync(path, newContent, 'utf8');
    }
}
build();