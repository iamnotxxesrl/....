require('dotenv').config();
const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const base64 = require('base-64');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// --- 1. Security & Logging Middleware ---

app.use(helmet());
app.use(morgan('dev'));
const limiter = rateLimit({
    windowMs: (process.env.RATE_LIMIT_WINDOW_MIN || 15) * 60 * 1000, 
    max: process.env.RATE_LIMIT_MAX || 100, 
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// --- 2. Static File & Frontend Route Handling ---

app.use(express.static('public'));
app.get('/view/*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 3. The Core Proxy Logic ---

const proxy = createProxyMiddleware({
    router: (req) => {
        const encodedUrl = req.path.split('/')[2];
        if (!encodedUrl) throw new Error('Encoded URL is required.');
        return base64.decode(encodedUrl);
    },
    // **FIXED:** This correctly removes the /view segment from the path
    // so the proxy can request the original URL.
    pathRewrite: (path, req) => {
        return path.replace(/^\/view/, '');
    },
    changeOrigin: true,
    selfHandleResponse: true,
    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        const contentType = proxyRes.headers['content-type'];
        const targetUrl = base64.decode(req.path.split('/')[2]);

        if (contentType && (contentType.includes('html') || contentType.includes('css') || contentType.includes('javascript'))) {
            let body = responseBuffer.toString('utf8');

            const rewriter = (match, p1, p2) => {
                try {
                    const absoluteUrl = new URL(p2, targetUrl).href;
                    return `${p1}/view/${base64.encode(absoluteUrl)}`;
                } catch (e) {
                    return match; 
                }
            };
            
            body = body.replace(/(href|src|action)=["']([^"']+)["']/g, rewriter);
            body = body.replace(/url\((['"]?)([^'"\)]+)(['"]?)\)/g, (match, p1, p2, p3) => {
                try {
                    const absoluteUrl = new URL(p2, targetUrl).href;
                    return `url(${p1}/view/${base64.encode(absoluteUrl)}${p3})`;
                } catch (e) {
                    return match;
                }
            });
            return body;
        }
        return responseBuffer; 
    }),
    logLevel: 'debug' 
});

// **FIXED:** This line now correctly attaches the proxy to the /view route
// so it can handle the incoming requests.
app.use('/view/:url', proxy);

// --- 4. Start The Server ---

const server = app.listen(PORT, () => {
    console.log(`✅ Everything Proxy server is running on http://localhost:${PORT}`);
});

server.on('upgrade', (req, socket, head) => {
    console.log('Attempting to upgrade to WebSocket...');
    proxy.upgrade(req, socket, head);
});
