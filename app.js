// Introduce any dependencies. Only several dependencies related to this example are included below:
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const app = express();
const PORT = 3000;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
console.log("CLIENTSEC", CLIENT_SECRET);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// app.post("/webhook-test", (request, response) => {
//     response.status(200).send("Received webhook subscription trigger");

//     const { url, method, body, headers, hostname } = request;

//     // Parse headers needed to validate signature
//     const signatureHeader = headers["x-hubspot-signature-v3"];
//     console.log("SignatureHeader", signatureHeader)
//     const timestampHeader = headers["x-hubspot-request-timestamp"];
//     console.log("TimestampHeader", timestampHeader)

//     // Validate timestamp
//     const MAX_ALLOWED_TIMESTAMP = 300000; // 5 minutes in milliseconds
//     const currentTime = Date.now();
//     if (currentTime - timestampHeader > MAX_ALLOWED_TIMESTAMP) {
//         console.log("Max allowed timestamp 5 minutes");
//         // Add any rejection logic here
//         return;
//     } else {
//         console.log("Timestamp is good");
//     }

//     // Concatenate request method, URI, body, and header timestamp
//     const uri = `https://${hostname}${url}`;
//     const rawString = `${method}${uri}${JSON.stringify(body)}${timestampHeader}`;
//     console.log("RawString", rawString)

//     // Create HMAC SHA-256 hash from resulting string above, then base64-encode it
//     const hashedString = crypto.createHmac("sha256", CLIENT_SECRET).update(rawString).digest("base64");
//     console.log("HashedString", hashedString)

//     // Validate signature: compare computed signature vs. signature in header
//     if (crypto.timingSafeEqual(Buffer.from(hashedString), Buffer.from(signatureHeader))) {
//         console.log("Signature matches! Request is valid.");
//         // Proceed with any request processing as needed.
//     } else {
//         console.log("Signature does not match: request is invalid");
//         // Add any rejection logic here.
//     }
// });

app.post("/webhook-test", (request, response) => {
    const { url, method, body, headers, hostname } = request;

    // Parse headers needed to validate signature
    const signatureHeader = headers["x-hubspot-signature-v3"];
    console.log("🔐 SignatureHeader:", signatureHeader);
    const timestampHeader = headers["x-hubspot-request-timestamp"];
    console.log("⏱ TimestampHeader:", timestampHeader);

    if (!signatureHeader || !timestampHeader) {
        console.log("❌ Missing signature or timestamp headers");
        return response.status(401).json({ error: "Missing required HubSpot headers" });
    }

    // Validate timestamp
    const MAX_ALLOWED_TIMESTAMP = 300000; // 5 minutes in milliseconds
    const currentTime = Date.now();
    if (currentTime - timestampHeader > MAX_ALLOWED_TIMESTAMP) {
        console.log("⚠️ Request timestamp too old (possible replay attack)");
        return response.status(401).json({ error: "Request timestamp too old" });
    } else {
        console.log("✅ Timestamp is valid");
    }

    // Construct the string to sign
    const uri = `https://${hostname}${url}`;
    const rawString = `${method}${uri}${JSON.stringify(body)}${timestampHeader}`;
    console.log("🧾 RawString:", rawString);

    // Compute HMAC SHA-256 hash
    const hashedString = crypto.createHmac("sha256", process.env.CLIENT_SECRET).update(rawString).digest("base64");
    console.log("🔑 Computed Signature:", hashedString);

    // Validate signature
    try {
        const valid = crypto.timingSafeEqual(Buffer.from(hashedString), Buffer.from(signatureHeader));

        if (valid) {
            console.log("✅ Signature matches! Request is valid.");
            return response.status(200).json({
                success: true,
                message: "Valid HubSpot webhook request",
            });
        } else {
            console.log("❌ Signature mismatch: request invalid");
            return response.status(401).json({
                success: false,
                error: "Invalid signature",
            });
        }
    } catch (error) {
        console.error("❌ Signature validation error:", error.message);
        return response.status(500).json({
            success: false,
            error: "Signature validation failed",
            details: error.message,
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
