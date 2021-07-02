const crypto = require('crypto');
const uuid = require('uuid');

const placeholderTag = 'hmac-acquia-placeholder';

module.exports.templateTags = [{
    name: 'hmacacquia',
    displayName: 'Request HMAC',
    description: 'HMAC of request as defined by acquia/http-hmac-spec',
    args: [
        {
            displayName: 'Realm',
            type: 'string',
            placeholder: 'HMAC provider'
        },
        {
            displayName: 'Id',
            type: 'string',
            placeholder: 'HMAC Id'
        },
        {
            displayName: 'Secret',
            type: 'string',
            placeholder: 'HMAC secret key'
        },
        {
            displayName: 'Custom headers',
            type: 'string',
            placeholder: '; separated headers to include'
        }
    ],
    run(context, realm, id, secret, headers) {
        if (context.renderPurpose !== 'send') {
            return `acquia-http-hmac realm="${encodeURIComponent(realm)}",id="${id}",nonce="5a578db7-cb15-4f4c-9673-8e83aaac0bae",version="2.0",headers="${headers}",signature="CC37sgZK/tPq7creSDH+LidvimsrdG27qFr3V47NGHk="`
        }

        return `<${placeholderTag}>${JSON.stringify({realm, id, secret, headers})}</${placeholderTag}>`
    }
}];

module.exports.requestHooks = [
    context => {
        const request = context.request;
        if (!request.hasHeader('Authorization')) {
            return;
        }
        const header = request.getHeader('Authorization').trim();
        if (!header.startsWith(`<${placeholderTag}>`) || !header.endsWith(`</${placeholderTag}>`)) {
            return;
        }

        const settings = extractSettings(header);
        settings.timestamp = Math.floor(Date.now() / 1000);
        settings.nonce = uuid.v4();
        settings.contentHash = null;

        const body = request.getBody();
        if (body.text) {
            settings.contentHash = hash(body.text);
            request.setHeader('X-Authorization-Content-SHA256', settings.contentHash);
        }

        request.setHeader('X-Authorization-Timestamp', settings.timestamp);
        request.setHeader('Authorization', buildAuthHeader(request, settings));
    }
];

function extractSettings(header) {
    const settings = JSON.parse(header.substring(
        placeholderTag.length + 2,
        header.length - placeholderTag.length - 3
    ));

    settings.headers = settings.headers
        ? settings.headers.split(';').map(header => header.trim().toLowerCase()).sort()
        : [];

    return settings;
}

function hash(content) {
    return crypto.createHash('sha256').update(content).digest('base64');
}

function hmac(content, secret) {
    return crypto.createHmac('sha256', Buffer.from(secret, 'base64')).update(content).digest('base64');
}

function computeSignature(request, settings) {
    const url = new URL(request.getUrl());
    const query = new URLSearchParams(request.getParameters().map(item => [item.name, item.value]));

    const parts = [
        request.getMethod().toUpperCase(),
        url.host,
        url.pathname,
        query.toString(),
        [
            ['id', settings.id],
            ['nonce', settings.nonce],
            ['realm', settings.realm],
            ['version', '2.0'],
        ].map(pair => pair[0] + '=' + encodeURIComponent(pair[1])).join('&')
    ];
    settings.headers.forEach(header => {
        if (request.hasHeader(header)) {
            parts.push(header + ':' + request.getHeader(header));
        }
    });
    parts.push(settings.timestamp);
    if (settings.contentHash) {
        parts.push(request.hasHeader('Content-type') ? request.getHeader('Content-type') : '');
        parts.push(settings.contentHash);
    }

    return hmac(parts.join("\n"), settings.secret);
}

function buildAuthHeader(request, settings) {
    return 'acquia-http-hmac ' + [
        ['realm', encodeURIComponent(settings.realm)],
        ['id', settings.id],
        ['nonce', settings.nonce],
        ['version', '2.0'],
        ['headers', settings.headers.join('%3B')],
        ['signature', computeSignature(request, settings)]
    ].map(pair => `${pair[0]}="${pair[1]}"`).join(',')
}
