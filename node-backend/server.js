const express = require('express');
const app = express();
const port = 3000;
const cors = require('cors');

const importantURLPatterns = [
    'api/security/saml/callback',
    'internal/security/me',
    'api/core/capabilities',
    'internal/security/login',
    '/internal/security/session',
    '/login?'
];

app.use(cors());
app.use(express.json({limit: '500mb'}));


// Add an endpoint that takes in a HAR file and returns the parsed data
app.post('/har', (req, res) => {
    const harFile = req.body.harFile;
    const harData = JSON.parse(harFile);

    const importantEntries = harData.log.entries.filter(entry => {
        const url = entry.request.url;
        return importantURLPatterns.some(pattern => url.includes(pattern));
    });

    // create a map of the important entries by url
    const importantEntriesMap = importantEntries.reduce((acc, entry) => {
        const url = entry.request.url;
        if (!acc[url]) {
            acc[url] = [];
        }
        acc[url].push(entry);
        return acc;
    }, {});

    res.json({importantEntriesMap});
});

app.post('/decode-base64', (req, res) => {
    const encodedStrings = req.body.encodedStrings;

    const decodedStrings = encodedStrings.map(encodedString => Buffer.from(encodedString, 'base64').toString('utf8'));

    const parsedObjects = [];
    decodedStrings.forEach(decodedString => {
        const inResponseTo = decodedString.match(/InResponseTo="([a-z0-9_]*)"/)[0];
        parsedObjects.push({inResponseTo});
    });

    res.json({parsedObjects});
});


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});