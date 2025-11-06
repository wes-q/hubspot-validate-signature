// Introduce any dependencies. Only several dependencies related to this example are included below:
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const app = express();
const CLIENT_SECRET = process.env.CLIENT_SECRET;
console.log("CLIENTSEC", CLIENT_SECRET);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.post("/webhook-test", (request, response) => {
    const { url, method, body, headers, hostname } = request;
    // console.log("URL", url);
    // console.log("Method", method);
    // console.log("Body", body);
    // console.log("TYPEOFBody", typeof body);
    // console.log("Hostname", hostname);

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

    const uri = `https://${hostname}${url}`;
    // This ensures consistent signature validation regardless of whether a body is present.
    const bodyString = Object.keys(body).length === 0 ? "" : JSON.stringify(body);
    const rawString = `${method}${uri}${bodyString}${timestampHeader}`;
    // const rawString = `${method}${uri}${JSON.stringify(body)}${timestampHeader}`;
    console.log("🧾 RawString:", rawString);

    // Compute HMAC SHA-256 hash
    const hashedString = crypto.createHmac("sha256", CLIENT_SECRET).update(rawString).digest("base64");
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

// require("dotenv").config();
// const express = require("express");
// const bodyParser = require("body-parser");
// const crypto = require("crypto");

// const app = express();
// const CLIENT_SECRET = process.env.CLIENT_SECRET;

// // Preserve raw body for signature validation
// app.use(
//     bodyParser.json({
//         verify: (req, res, buf) => {
//             req.rawBody = buf.toString();
//         },
//     })
// );

// app.post("/webhook-test", (req, res) => {
//     const { url, method, headers, hostname } = req;
//     const signatureHeader = headers["x-hubspot-signature-v3"];
//     const timestampHeader = headers["x-hubspot-request-timestamp"];

//     if (!signatureHeader || !timestampHeader) {
//         return res.status(401).json({ error: "Missing required HubSpot headers" });
//     }

//     // const MAX_ALLOWED_TIMESTAMP = 300000; // 5 min
//     // const currentTime = Date.now();
//     // if (currentTime - timestampHeader > MAX_ALLOWED_TIMESTAMP) {
//     //     return res.status(401).json({ error: "Request timestamp too old" });
//     // }

//     const uri = `https://${hostname}${url}`;
//     const rawString = `${method}${uri}${req.rawBody}${timestampHeader}`;

//     const computedSignature = crypto.createHmac("sha256", CLIENT_SECRET).update(rawString).digest("base64");

//     console.log("🧩 HubSpot Signature Debug Start --------------------");
//     console.log("🔹 Method:", method);
//     console.log("🔹 URL:", url);
//     console.log("🔹 Hostname:", hostname);
//     console.log("🔹 Header Signature:", signatureHeader);
//     console.log("🔹 Header Timestamp:", timestampHeader);
//     console.log("🧾 Raw Body:", req.rawBody);
//     console.log("🧾 Constructed Signed String:", rawString);
//     console.log("🔐 Computed Signature:", computedSignature);
//     console.log("🧩 HubSpot Signature Debug End ----------------------");

//     try {
//         const valid = crypto.timingSafeEqual(Buffer.from(computedSignature), Buffer.from(signatureHeader));

//         if (valid) {
//             console.log("✅ Signature matches! Request is valid.");
//             return res.status(200).json({ success: true, message: "Valid webhook" });
//         } else {
//             console.log("❌ Signature mismatch: request invalid");
//             return res.status(401).json({ success: false, error: "Invalid signature" });
//         }
//     } catch (error) {
//         console.error("❌ Signature validation error:", error.message);
//         return res.status(500).json({ error: "Validation failed", details: error.message });
//     }
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

// require("dotenv").config();
// const express = require("express");
// const bodyParser = require("body-parser");
// const crypto = require("crypto");

// const app = express();
// const CLIENT_SECRET = process.env.CLIENT_SECRET;

// // Preserve raw body for signature validation
// app.use(
//     bodyParser.json({
//         verify: (req, res, buf) => {
//             req.rawBody = buf.toString();
//         },
//     })
// );

// app.post("/webhook-test", (req, res) => {
//     const { url, method, headers, hostname } = req;
//     const signatureHeader = headers["x-hubspot-signature-v3"];
//     const timestampHeader = headers["x-hubspot-request-timestamp"];

//     if (!signatureHeader || !timestampHeader) {
//         return res.status(401).json({ error: "Missing required HubSpot headers" });
//     }

//     // const MAX_ALLOWED_TIMESTAMP = 300000; // 5 min
//     // const currentTime = Date.now();
//     // if (currentTime - timestampHeader > MAX_ALLOWED_TIMESTAMP) {
//     //     return res.status(401).json({ error: "Request timestamp too old" });
//     // }

//     const uri = `https://${hostname}${url}`;
//     const rawString = `${method}${uri}${req.rawBody}${timestampHeader}`;

//     const computedSignature = crypto.createHmac("sha256", CLIENT_SECRET).update(rawString).digest("base64");

//     console.log("🧩 HubSpot Signature Debug Start --------------------");
//     console.log("🔹 Method:", method);
//     console.log("🔹 URL:", url);
//     console.log("🔹 Hostname:", hostname);
//     console.log("🔹 Header Signature:", signatureHeader);
//     console.log("🔹 Header Timestamp:", timestampHeader);
//     console.log("🧾 Raw Body:", req.rawBody);
//     console.log("🧾 Constructed Signed String:", rawString);
//     console.log("🔐 Computed Signature:", computedSignature);
//     console.log("🧩 HubSpot Signature Debug End ----------------------");

//     try {
//         const valid = crypto.timingSafeEqual(Buffer.from(computedSignature), Buffer.from(signatureHeader));

//         if (valid) {
//             console.log("✅ Signature matches! Request is valid.");
//             return res.status(200).json({ success: true, message: "Valid webhook" });
//         } else {
//             console.log("❌ Signature mismatch: request invalid");
//             return res.status(401).json({ success: false, error: "Invalid signature" });
//         }
//     } catch (error) {
//         console.error("❌ Signature validation error:", error.message);
//         return res.status(500).json({ error: "Validation failed", details: error.message });
//     }
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
