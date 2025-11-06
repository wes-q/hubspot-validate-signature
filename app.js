// Introduce any dependencies. Only several dependencies related to this example are included below:
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.post("/webhook-test", (request, response) => {
    response.status(200).send("Received webhook subscription trigger");

    const { url, method, body, headers, hostname } = request;

    // Parse headers needed to validate signature
    const signatureHeader = headers["x-hubspot-signature-v3"];
    const timestampHeader = headers["x-hubspot-request-timestamp"];

    // Validate timestamp
    const MAX_ALLOWED_TIMESTAMP = 300000; // 5 minutes in milliseconds
    const currentTime = Date.now();
    if (currentTime - timestampHeader > MAX_ALLOWED_TIMESTAMP) {
        console.log("Max allowed timestamp 5 minutes");
        // Add any rejection logic here
        return;
    }

    // Concatenate request method, URI, body, and header timestamp
    const uri = `https://${hostname}${url}`;
    const rawString = `${method}${uri}${JSON.stringify(body)}${timestampHeader}`;

    // Create HMAC SHA-256 hash from resulting string above, then base64-encode it
    const hashedString = crypto.createHmac("sha256", process.env.CLIENT_SECRET).update(rawString).digest("base64");

    // Validate signature: compare computed signature vs. signature in header
    if (crypto.timingSafeEqual(Buffer.from(hashedString), Buffer.from(signatureHeader))) {
        console.log("Signature matches! Request is valid.");
        // Proceed with any request processing as needed.
    } else {
        console.log("Signature does not match: request is invalid");
        // Add any rejection logic here.
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
