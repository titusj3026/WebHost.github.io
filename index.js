const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const aes = require("aes-js");
const argon2 = require("argon2");
const mime = require("mime");
const path = require("path");
const moment = require("moment");
const multer = require("multer");
const helmet = require("helmet");
const config = require("./config");
const {escape: escapeHTML} = require("html-escaper");
const chokidar = require("chokidar");
const providers = require("./http-providers");
const nUtil = require("util");
const filesize = require("filesize").partial({base: 10, round: 1}); // meGAbytes, not meBIbytes


let apiKeys = [];
const updateKeys = () => {
  fs.readFile("keys.txt", (err, buf) => {
    if (err) return console.error(err);
    const keys = buf.toString().split(/[\n\r]+/g).map(keyWithComment => keyWithComment.split("#")[0].trim());
    apiKeys = keys;
    if (oauth) oauth.updateKeys(keys);
    if (cloudflare) cloudflare.updateKeys(keys);
  });
};
updateKeys();
const keyWatcher = chokidar.watch("keys.txt");
keyWatcher.on("change", () => {
  updateKeys();
  console.log("Reloaded keys!");
});

let domains = [];
const updateDomains = () => {
  fs.readFile("domains.txt", (err, buf) => {
    if (err) return console.error(err);
    domains = buf.toString().split(/[\n\r]+/g).map(d => d.trim()).filter(d => d);
    if (cloudflare) cloudflare.updateDomains(domains);
  });
};
const domainWatcher = chokidar.watch("domains.txt");
domainWatcher.on("change", () => {
  updateDomains();
  console.log("Updated domains!");
});
updateDomains();

const cooldowns = new Map();
const shortCooldowns = new Map();

const {encryptionHashes, deletionHashes, shortUrls, shortDeletionHashes,
  embedData, expiryData, domainAnalytics} = require("./databases");
const {deleteFile} = require("./funcs");
const oauth = config.oauth ? require("./oauth") : null;
const cloudflare = config.cloudflare ? require("./cloudflare") : null;

const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const promRandomInt = nUtil.promisify(crypto.randomInt);
const promRandomBytes = nUtil.promisify(crypto.randomBytes);
const cryptoRandomStr = async (size, characters = base64Chars) => {
  let res = "";
  for (const _ of Array(size)) {
    res += characters[await promRandomInt(0, characters.length)];
  }
  return res;
};
const recursiveFindFile = async (size = 14, extension, depth = 0) => {
  const possibleName = await cryptoRandomStr(size);
  if (depth >= 16) return {
    success: false,
    error: "Tried too many names - try increasing your name length."
  };
  try {
    await fs.promises.access(`images/${possibleName}.${extension}`);
    return await recursiveFindFile(size, extension, depth + 1);
  } catch (e) {
    return {
      success: true,
      name: `${possibleName}.${extension}`
    };
  }
};

const app = express();
app.use(helmet({
  noCache: false,
  hsts: false,
  contentSecurityPolicy: false
}));

if (config.http.trustProxy) {
  app.enable("trust proxy");
}

if (config.http.https) {
  app.use((req, res, next) => {
    if (!req.secure) return res.redirect(`https://${req.hostname}:${config.http.https.port}${req.url}`);
    next();
  });
}

app.use((req, res, next) => {
  if (req.url.split("/").includes("..")) return res.status(400).send({success: false, error: "Bad request"});
  if (path.extname(req.url)) res.set("X-Robots-Tag", "noindex");
  next();
});

if (oauth !== null) {
  oauth.handle(app);
}
if (cloudflare !== null) {
  cloudflare.handle(app);
}

app.use(express.static("web"));

function replaceVariables(str, context) {
  return str.replace(/\[([A-Za-z0-9_\-]+)\]/g, (match, p1) => {
    if (!context.has(p1.toUpperCase())) return match;
    return context.get(p1.toUpperCase());
  });
}

const FILE_SIZE_LIMIT = config.uploading.sizeLimit;
const multipartMiddleware = multer({
  limits: {
    fileSize: FILE_SIZE_LIMIT,
    fields: 0,
    files: 1
  },
  storage: multer.memoryStorage()
}).any();
app.post("/upload", (req, res, next) => {
  multipartMiddleware(req, res, err => {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({success: false, error: "Invalid multipart body"});
    }
    if (req.files && req.files[0]) req.file = req.files[0];
    if (req.file) return next();
    let body = Buffer.from([]);
    req.isTooLarge = false;
    req.on("data", chunk => {
      if (!req.isTooLarge) body = Buffer.concat([body, chunk]);
      if (body.length > FILE_SIZE_LIMIT) {
        req.isTooLarge = true;
        body = Buffer.from([]);
      }
    });
    req.on("end", function() {
      req.file = {
        buffer: body,
        mimetype: req.get("Content-Type")
      };
      next();
    });
  });
}, async (req, res) => {
  if (req.isTooLarge) return res.status(413).send({success: false, error: "Upload file too large"});
  let extension;
  try {
    extension = mime.getExtension(req.file.mimetype);
  } catch (e) {
    return res.status(415).json({success: false, error: "Bad Content-Type"});
  }
  const doEncryption = req.query.encryption === "yes";
  if (!extension || ["exe", "com", "js", "vbs", "msi", "dmg", "css", "html", "py"].includes(extension)) return res.status(403).json({success: false, error: "Forbidden file extension"});
  const key = (req.get("Authorization") || "").trim();
  if (!key || !apiKeys.includes(key)) return res.status(401).json({success: false, error: "Invalid API key"});
  const cooldown = cooldowns.get(key) || 0;
  if (cooldown > Date.now()) return res.status(429).json({success: false, error: `Ratelimited - wait ${cooldown - Date.now()}ms`});
  cooldowns.set(key, Date.now() + config.uploading.uploadRatelimit);
  let nameLength = ~~req.query.nameLength || 14;
  if (nameLength < 6 || nameLength > 24) return res.status(400).json({success: false, error: "Invalid name length"});
  const nameData = await recursiveFindFile(nameLength, extension);
  if (!nameData.success) return res.status(500).json({success: false, error: `Error while finding name: ${nameData.error}`});
  const name = nameData.name;
  const randomChoices = (req.query.random || "").split(",");
  const randomChoice = randomChoices[~~(randomChoices.length * Math.random())];
  let embed;

  if (req.query.embed === "yes") {
    if (!["image/", "video/"].find(pref => req.file.mimetype.startsWith(pref))) return res.status(400).json({success: false, error: "Cannot embed a non-visual upload!"});
    embed = {
      color: 0xFFFFFF,
      text: config.uploading.name,
      video: req.file.mimetype.startsWith("video/")
    };

    const dateFormat = req.query.embedMDY === "yes" ? "M/D/y" : "D/M/y";

    let now = moment();
    if (req.query.embedTimezone) {
      const offset = parseInt(req.query.embedTimezone);
      if (!Number.isInteger(offset) || offset < -23 || offset > 23) return res.status(400).json({
        success: false,
        error: "Invalid timezone offset!"
      });
      now = now.add(offset, "hours");
    }
    embed.uploadedAt = now.format(`h:mm A ${dateFormat}`);

    const context = new Map();
    context.set("UPLOAD_TIME", now.format("h:mm A"));
    context.set("UPLOAD_DATE", now.format(dateFormat));
    const extension = path.extname(name);
    context.set("UPLOAD_EXTENSION", extension.slice(1))
    context.set("UPLOAD_NAME", path.basename(name, extension));
    context.set("UPLOAD_SIZE", filesize(req.file.buffer.length).toUpperCase());

    if (req.query.embedText) {
      if (req.query.embedText.length > 480) return res.status(400).json({success: false, error: "Embed text too long!"});
      embed.text = replaceVariables(req.query.embedText, context);
    }

    if (req.query.embedColor === "RANDOM") embed.color = ~~(Math.random() * 0x1000000);
    else if (req.query.embedColor && req.query.embedColor.match(/^\d+$/)) {
      const num = ~~req.query.embedColor;
      if (num < 0 || num > 0xFFFFFF) return res.status(400).json({success: false, error: "Invalid color!"});
      embed.color = num;
    } else {
      const match = (req.query.embedColor || "").match(/^#([A-Fa-f0-9]{6})$/);
      if (match) {
        const num = parseInt(match[1], 16);
        if (num < 0 || num > 0xFFFFFF || Number.isNaN(num)) return res.status(400).json({success: false, error: "Not sure how you did this, but invalid hex code?"});
        embed.color = num;
      }
    }

    if (req.query.embedDescription) {
      if (req.query.embedDescription.length > 480) return res.status(400).json({success: false, error: "Embed description too long!"});
      embed.description = replaceVariables(req.query.embedDescription, context);
    }
    if (req.query.embedHeader) {
      if (req.query.embedHeader.length > 480) return res.status(400).json({success: false, error: "Embed header too long!"});
      embed.header = replaceVariables(req.query.embedHeader, context);
    }
    if (req.query.embedAuthor) {
      if (req.query.embedAuthor.length > 480) return res.status(400).json({success: false, error: "Embed author too long!"});
      embed.author = replaceVariables(req.query.embedAuthor, context);
    }
  }

  let expiry;
  if (req.query.expire === "yes") {
    expiry = {};
    if (req.query.expireUses) {
      const num = ~~req.query.expireUses;
      if (num > 10 || num < 1) return res.status(400).json({success: false, error: "Uses must be between 1-10"});
      expiry.usesLeft = num;
    }
    if (req.query.expireTime) {
      const num = +req.query.expireTime;
      if (num < 0 || num > (1000 * 60 * 60 * 24)) return res.status(400).json({success: false, error: "Time must be less than a day!"});
      expiry.time = Date.now() + num;
    }
    if (!req.query.expireUses && !req.query.expireTime) return res.status(400).json({success: false, error: "No expiry data provided!"});
  }
  if (doEncryption) {
    const keyLength = ~~req.query.keyLength || (req.query.encryptionKey || {}).length || 0;
    if (keyLength > config.uploading.keyLengthLimit) return res.status(400).json({success: false, error: "Encryption key too large"});
    const encryptionKey = Buffer.from(req.query.encryptionKey || await cryptoRandomStr(~~req.query.keyLength || 16));
    const aesCtr = new aes.ModeOfOperation.ctr(crypto.createHash("sha256").update(encryptionKey).digest());
    fs.writeFile(`images/${name}`, Buffer.from(aesCtr.encrypt(req.file.buffer)), async err => {
      if (err) {
        console.error(err);
        res.status(500).json({success: false, error: "Could not save image!"});
      }
      else {
        try {
          const encKeyStr = encryptionKey.toString();
          const hash = await argon2.hash(encKeyStr);
          encryptionHashes.set(name, {hash, legacy: false});
          const deletionKey = (await promRandomBytes(64)).toString("hex");
          deletionHashes.set(name, await argon2.hash(deletionKey));
          console.log(`API key ${key} uploaded file ${name}`);
          let json = {
            success: true,
            encryptionKey: encKeyStr,
            name,
            deletionKey
          };
          if (randomChoice) json.random = randomChoice;
          json.deducedURL = `${req.secure ? "https" : "http"}://${encodeURI(json.random || req.get("Host"))}/${encodeURIComponent(json.encryptionKey)}/${encodeURIComponent(json.name)}`;
          if (embed) embedData.set(name, embed);
          if (expiry) expiryData.set(name, expiry);
          const uploads = domainAnalytics.get(req.get("Host")) || 0;
          domainAnalytics.set(req.get("Host"), uploads + 1);
          if (req.query.onlyURL === "yes") res.status(200).type("text/plain").send(json.deducedURL);
          else res.status(200).json(json);
        } catch (e) {
          console.error(e);
          res.status(500).json({success: false, error: "Error while saving keys!"});
        }
      }
    });
  } else {
    fs.writeFile(`images/${name}`, req.file.buffer, async err => {
      if (err) {
        console.error(err);
        res.status(500).json({success: false, error: "Could not save image!"});
      }
      else {
        try {
          const deletionKey = (await promRandomBytes(64)).toString("hex");
          deletionHashes.set(name, await argon2.hash(deletionKey));
          console.log(`API key ${key} uploaded file ${name}`);
          let json = {success: true, name, deletionKey};
          if (randomChoice) json.random = randomChoice;
          json.deducedURL = `${req.secure ? "https" : "http"}://${encodeURI(json.random || req.get("Host"))}/${encodeURIComponent(json.name)}`;
          if (embed) embedData.set(name, embed);
          if (expiry) expiryData.set(name, expiry);
          const uploads = domainAnalytics.get(req.get("Host")) || 0;
          domainAnalytics.set(req.get("Host"), uploads + 1);
          if (req.query.onlyURL === "yes") res.status(200).type("text/plain").send(json.deducedURL);
          else res.status(200).json(json);
        } catch (e) {
          console.error(e);
          res.status(500).json({success: false, error: "Error while saving keys!"});
        }
      }
    });
  }
});

const ZW_BASE = ["\u200C", "\u200D", "\u200E"];
app.get("/shorten", async (req, res) => {
  const url = req.query.url;
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {}
  if (!urlObj) return res.status(400).json({success: false, error: "Invalid URL"});
  const key = (req.get("Authorization") || "").trim();
  if (!apiKeys.includes(key) || key.trim() === "") return res.status(401).json({success: false, error: "Invalid API key"});
  const cooldownAt = shortCooldowns.get(key) || 0;
  if (cooldownAt > Date.now()) return res.status(429).json({success: false, error: `Ratelimited - wait ${cooldownAt - Date.now()}ms`});
  shortCooldowns.set(key, Date.now() + 2500);
  const deletionKey = (await promRandomBytes(64)).toString("hex");
  const doZW = req.query.mode === "zw";
  const name = doZW ? await cryptoRandomStr(31, ZW_BASE) : await cryptoRandomStr(8);
  shortDeletionHashes.set(name, await argon2.hash(deletionKey));
  const randomChoices = (req.query.random || "").split(",");
  const randomChoice = randomChoices[~~(randomChoices.length * Math.random())];
  shortUrls.set(name, url);
  let json = {name, deletionKey};
  if (randomChoice) json.random = randomChoice;
  console.log(`API key ${key} shortened URL ${url}`);
  res.status(200).json(json);
});

app.get("/delete/:key/:name", async (req, res) => {
  try {
    const hash = deletionHashes.get(req.params.name);
    if (!hash) return res.status(404).json({success: false, error: "File does not exist"});
    if (!await argon2.verify(hash, req.params.key)) return res.status(401).json({success: false, error: "Invalid deletion key!"});
    try {
      await deleteFile(req.params.name);
      res.redirect("/deleted");
    } catch(e) {
      console.error(e);
      res.status(500).json({success: false, error: "An error occurred while deleting the file!"});
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({success: false, error: "An error occurred."});
  }
});

app.get("/delete-short/:key/:name", async (req, res) => {
  const hash = shortDeletionHashes.get(req.params.name);
  if (!hash) return res.status(404).json({success: false, error: "Shortened URL does not exist"});
  if (!await argon2.verify(hash, req.params.key)) return res.status(401).json({success: false, error: "Invalid deletion key!"});
  shortDeletionHashes.delete(req.params.name);
  shortUrls.delete(req.params.name);
  res.redirect("/deleted-short");
});

app.get(["/:encKey/:name", "/raw/:encKey/:name"], async (req, res, next) => {
  try {
    const encryptionHash = encryptionHashes.get(req.params.name);
    if (!encryptionHash) return next();
    if (!await argon2.verify(encryptionHash.hash, req.params.encKey)) return res.status(401).json({success: false, error: "Invalid decryption key!"});
    const embed = embedData.get(req.params.name);
    if (!req.url.startsWith("/raw/") && embed) {
      return res.type("text/html").send(`<!DOCTYPE html>
<html lang="en" prefix="og: http://ogp.me/ns#">
<head>
<link rel="alternate" type="application/json+oembed" href="https://${escapeHTML(req.get("Host"))}/oembed?name=${escapeHTML(encodeURIComponent(req.params.name))}" title="OEmbed">
<meta property="og:title" content="${escapeHTML(embed.text || config.name)}">
<meta property="theme-color" content="#${("000000" + embed.color.toString(16).toUpperCase()).slice(-6)}">
<meta property="${embed.video ? "twitter:player" : "og:image"}" content="https://${escapeHTML(req.get("Host"))}/raw/${escapeHTML(encodeURIComponent(req.params.encKey))}/${escapeHTML(encodeURIComponent(req.params.name))}">
<meta name="twitter:card" content="${embed.video ? "player" : "summary_large_image"}">
<meta property="og:description" content="${embed.description ? escapeHTML(embed.description) : `Uploaded at ${embed.uploadedAt}`}">
</head>
<body>
<script>location.pathname = "/raw" + location.pathname;</script>
</body>
</html>`);
    }
    let expiry = expiryData.get(req.params.name);
    if (expiry) {
      if (expiry.time < Date.now()) {
        try {
          await deleteFile(req.params.name);
          next();
        } catch(e) {
          console.error(e);
          res.status(500).json({success: false, error: "An error occurred while deleting the file!"});
        }
        return;
      }
      if (expiry.usesLeft) {
        expiry.usesLeft--;
        if (!expiry.usesLeft) {
          try {
            await deleteFile(req.params.name);
            next();
          } catch(e) {
            console.error(e);
            res.status(500).json({success: false, error: "An error occurred while deleting the file!"});
          }
          return;
        }
        expiryData.set(req.params.name, expiry);
      }
    }
    fs.readFile(`images/${req.params.name}`, (err, buf) => {
      if (err) return res.status(500).json({success: false, error: "An error occurred while reading the file."});
      try {
        const aesCtr = new aes.ModeOfOperation.ctr(encryptionHash.legacy ? Buffer.from(req.params.encKey) : crypto.createHash("sha256").update(req.params.encKey).digest());
        const decrypted = aesCtr.decrypt(buf);
        res.type(mime.getType(path.extname(req.params.name))).send(Buffer.from(decrypted));
      } catch (e) {
        console.error(e);
        return res.status(500).json({success: false, error: "An error occurred."});
      }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({success: false, error: "An error occurred."});
  }
});

app.get(["/:name", "/raw/:name"], async (req, res, next) => {
  try {
    const deletionKey = deletionHashes.get(req.params.name);
    if (!deletionKey) return next();
    const encryptionHash = encryptionHashes.get(req.params.name);
    if (encryptionHash) return res.status(401).json({success: false, error: "This image is encrypted!"});
    const embed = embedData.get(req.params.name);
    if (!req.url.startsWith("/raw/") && embed) {
      return res.type("text/html").send(`<!DOCTYPE html>
<html prefix="og: http://ogp.me/ns#">
<head>
<link rel="alternate" type="application/json+oembed" href="https://${escapeHTML(req.get("Host"))}/oembed?name=${escapeHTML(encodeURIComponent(req.params.name))}" title="OEmbed">
<meta property="og:title" content="${escapeHTML(embed.text || config.name)}">
<meta property="theme-color" content="#${("000000" + embed.color.toString(16).toUpperCase()).slice(-6)}">
<meta property="${embed.video ? "twitter:player" : "og:image"}" content="https://${escapeHTML(req.get("Host"))}/raw/${escapeHTML(encodeURIComponent(req.params.name))}">
<meta name="twitter:card" content="${embed.video ? "player" : "summary_large_image"}">
<meta property="og:description" content="${embed.description ? escapeHTML(embed.description) : `Uploaded at ${embed.uploadedAt}`}">
</head>
<body>
<script>location.pathname = "/raw" + location.pathname;</script>
</body>
</html>`);
    }
    let expiry = expiryData.get(req.params.name);
    if (expiry) {
      if (expiry.time < Date.now()) {
        try {
          await deleteFile(req.params.name);
          next();
        } catch(e) {
          console.error(e);
          res.status(500).json({success: false, error: "An error occurred while deleting the file!"});
        }
        return;
      }
      if (expiry.usesLeft) {
        expiry.usesLeft--;
        if (!expiry.usesLeft) {
          try {
            await deleteFile(req.params.name);
            next();
          } catch(e) {
            console.error(e);
            res.status(500).json({success: false, error: "An error occurred while deleting the file!"});
          }
          return;
        }
        expiryData.set(req.params.name, expiry);
      }
    }
    fs.readFile(`images/${req.params.name}`, (err, buf) => {
      if (err) return res.status(500).json({success: false, error: "An error occurred while reading the file."});
      try {
        res.type(mime.getType(path.extname(req.params.name))).send(buf);
      } catch (e) {
        console.error(e);
        return res.status(500).json({success: false, error: "An error occurred."});
      }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({success: false, error: "An error occurred."});
  }
});

app.get("/oembed", async (req, res) => {
  if (!req.query.name || !embedData.has(req.query.name)) return res.status(404).json({success: false, error: "File not found"});
  const embed = embedData.get(req.query.name);

  let json = {
    type: "link",
    version: "1.0"
  };
  if (embed.header) json.provider_name = embed.header;
  if (embed.author) json.author_name = embed.author;

  res.json(json);
});

app.get("/:name", (req, res, next) => {
  const url = shortUrls.get(req.params.name);
  if (!url) return next();
  res.redirect(url);
});

app.get("/api/domains", (req, res) => {
  res.json(domains);
});

app.use((req, res) => {
  res.status(404).type("text/plain").send("this is a 404");
});

if (!(config.http.protocol in providers)) {
  console.error(`Protocol "${config.http.protocol}" does not exist!`);
  process.exit(1);
}

const provider = providers[config.http.protocol]();
if (!config.http.https && !provider.createHTTP) {
  console.error(`Protocol "${config.http.protocol}" does not support non-encrypted connections!`);
  process.exit(1);
}

if (provider.createHTTP) {
  provider.createHTTP(app).listen(config.http.port, function() {
    console.log(`Unsecured server is listening on port ${config.http.port}`);
  });
}
if (provider.createHTTPS && config.http.https) {
  provider.createHTTPS({
    key: fs.readFileSync(config.http.https.key),
    cert: fs.readFileSync(config.http.https.cert)
  }, app).listen(config.http.https.port, function() {
    console.log(`Secured server is listening on port ${config.http.https.port}`);
  });
}