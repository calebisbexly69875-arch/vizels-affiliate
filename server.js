require("dotenv").config();

const cookieParser = require("cookie-parser");
const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const db = new Database("affiliates.db");

app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  }
}));

db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  discount_code TEXT UNIQUE NOT NULL,
  discord_username TEXT NOT NULL,
  verified INTEGER DEFAULT 0,
  approved INTEGER DEFAULT 0,
  denied INTEGER DEFAULT 0,
  verification_code TEXT,
  code_expires INTEGER,
  sales INTEGER DEFAULT 0,
  commission REAL DEFAULT 0,
  clicks INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  discount_code TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS signup_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  created_at INTEGER NOT NULL
)
`).run();

try { db.prepare("ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 0").run(); } catch {}
try { db.prepare("ALTER TABLE users ADD COLUMN denied INTEGER DEFAULT 0").run(); } catch {}
try { db.prepare("ALTER TABLE users ADD COLUMN clicks INTEGER DEFAULT 0").run(); } catch {}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function makeCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function siteUrl(req) {
  return process.env.SITE_URL || `${req.protocol}://${req.get("host")}`;
}

function isAdmin(req) {
  return req.query.key === process.env.ADMIN_KEY;
}

function cleanAffiliateCode(code) {
  return String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function isSignupRateLimited(ip) {
  const fifteenMinutesAgo = Date.now() - 15 * 60 * 1000;

  db.prepare("DELETE FROM signup_attempts WHERE created_at < ?").run(fifteenMinutesAgo);

  const count = db.prepare("SELECT COUNT(*) AS total FROM signup_attempts WHERE ip = ?").get(ip).total;

  if (count >= 3) return true;

  db.prepare("INSERT INTO signup_attempts (ip, created_at) VALUES (?, ?)").run(ip, Date.now());
  return false;
}

app.get("/", (req, res) => {
  const ref = cleanAffiliateCode(req.query.ref);

  if (ref) {
    const user = db.prepare("SELECT * FROM users WHERE discount_code = ? AND approved = 1").get(ref);

    if (user) {
      db.prepare("UPDATE users SET clicks = clicks + 1 WHERE discount_code = ?").run(ref);
      db.prepare("INSERT INTO clicks (discount_code, ip, user_agent) VALUES (?, ?, ?)").run(
        ref,
        req.ip,
        req.get("user-agent") || ""
      );

      res.cookie("affiliate_ref", ref, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production"
      });
    }
  }

  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/signup", async (req, res) => {
  try {
    if (isSignupRateLimited(req.ip)) {
      return res.send("Too many signup attempts. Please try again later.");
    }

    const { firstName, lastName, email, password, discountCode, discordUsername, agreement } = req.body;

    if (!firstName || !lastName || !email || !password || !discountCode || !discordUsername || agreement !== "on") {
      return res.send("Missing info or agreement not checked.");
    }

    if (password.length < 8) {
      return res.send("Password must be at least 8 characters.");
    }

    const cleanCode = cleanAffiliateCode(discountCode);

    if (cleanCode.length < 3) {
      return res.send("Discount code must be at least 3 letters/numbers.");
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const verificationCode = makeCode();
    const codeExpires = Date.now() + 10 * 60 * 1000;

    db.prepare(`
      INSERT INTO users 
      (email, password_hash, first_name, last_name, discount_code, discord_username, verification_code, code_expires)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(email, passwordHash, firstName, lastName, cleanCode, discordUsername, verificationCode, codeExpires);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "VizelsTweaks Verification Code",
      text: `Your verification code is: ${verificationCode}\n\nThis code expires in 10 minutes.`
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.OWNER_EMAIL,
      subject: "New VizelsTweaks Affiliate Signup",
      text: `
New Affiliate Signup

First Name: ${firstName}
Last Name: ${lastName}
Email: ${email}
Discount Code: ${cleanCode}
Discord Username: ${discordUsername}
Status: Waiting for email verification
      `
    });

    res.redirect(`/verify.html?email=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error(err);
    res.send("Signup failed. Email or discount code may already be used.");
  }
});

app.post("/verify", async (req, res) => {
  const { email, code } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user) return res.send("Account not found.");
  if (user.verified) return res.redirect("/login.html");
  if (Date.now() > user.code_expires) return res.send("Code expired.");
  if (code !== user.verification_code) return res.send("Wrong code.");

  db.prepare(`
    UPDATE users 
    SET verified = 1, verification_code = NULL, code_expires = NULL
    WHERE email = ?
  `).run(email);

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: process.env.OWNER_EMAIL,
    subject: "Affiliate Verified - Needs Approval",
    text: `
Affiliate verified their email.

Name: ${user.first_name} ${user.last_name}
Email: ${user.email}
Code: ${user.discount_code}
Discord: ${user.discord_username}

Approve:
${siteUrl(req)}/admin/approve/${user.discount_code}?key=${process.env.ADMIN_KEY}

Deny:
${siteUrl(req)}/admin/deny/${user.discount_code}?key=${process.env.ADMIN_KEY}
    `
  });

  res.redirect("/login.html");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user) return res.send("Account not found.");
  if (!user.verified) return res.send("Please verify your email first.");
  if (user.denied) return res.send("Your affiliate application was denied.");

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.send("Wrong password.");

  req.session.userId = user.id;
  res.redirect("/dashboard");
});

app.get("/dashboard", (req, res) => {
  if (!req.session.userId) return res.redirect("/login.html");

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
  const referralLink = `${siteUrl(req)}/?ref=${user.discount_code}`;

  if (!user.approved) {
    return res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Pending Approval</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="page">
    <div class="card">
      <div class="badge">PENDING APPROVAL</div>
      <h1>Application Received</h1>
      <p class="subtitle">Your email is verified. Your application is waiting for review.</p>

      <div class="dashboard-grid">
        <div class="stat-card">
          <span>Email</span>
          <strong>Verified</strong>
        </div>
        <div class="stat-card">
          <span>Status</span>
          <strong>Pending</strong>
        </div>
        <div class="stat-card">
          <span>Code</span>
          <strong>${user.discount_code}</strong>
        </div>
      </div>

      <form action="/logout" method="POST">
        <button type="submit">Logout</button>
      </form>
    </div>
  </div>
</body>
</html>
    `);
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Affiliate Dashboard</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="page">
    <div class="card dashboard-card">
      <div class="badge">AFFILIATE DASHBOARD</div>
      <h1>Welcome, ${user.first_name}</h1>
      <p class="subtitle">Your affiliate account is approved and active.</p>

      <div class="dashboard-grid">
        <div class="stat-card">
          <span>Clicks</span>
          <strong>${user.clicks}</strong>
        </div>
        <div class="stat-card">
          <span>Sales</span>
          <strong>${user.sales}</strong>
        </div>
        <div class="stat-card">
          <span>Commission</span>
          <strong>$${Number(user.commission).toFixed(2)}</strong>
        </div>
      </div>

      <div class="grid">
        <div class="info-box">
          <h2>Account</h2>
          <div class="step"><strong>Name:</strong> ${user.first_name} ${user.last_name}</div>
          <div class="step"><strong>Email:</strong> ${user.email}</div>
          <div class="step"><strong>Discord:</strong> ${user.discord_username}</div>
          <div class="step"><strong>Status:</strong> Approved</div>
        </div>

        <div class="info-box">
          <h2>Promote</h2>

          <label class="mini-label">Discount Code</label>
          <div class="copy-row">
            <input id="codeBox" value="${user.discount_code}" readonly>
            <button type="button" onclick="copyText('codeBox')">Copy</button>
          </div>

          <label class="mini-label">Referral Link</label>
          <div class="copy-row">
            <input id="linkBox" value="${referralLink}" readonly>
            <button type="button" onclick="copyText('linkBox')">Copy</button>
          </div>

          <p class="small-note">Share your referral link. Clicks are tracked automatically.</p>
        </div>
      </div>

      <form action="/logout" method="POST">
        <button type="submit">Logout</button>
      </form>
    </div>
  </div>

  <script>
    function copyText(id) {
      const box = document.getElementById(id);
      box.select();
      box.setSelectionRange(0, 99999);
      navigator.clipboard.writeText(box.value);
      alert("Copied!");
    }
  </script>
</body>
</html>
  `);
});

app.get("/admin/approve/:code", async (req, res) => {
  if (!isAdmin(req)) return res.send("Not allowed.");

  const code = cleanAffiliateCode(req.params.code);
  const user = db.prepare("SELECT * FROM users WHERE discount_code = ?").get(code);

  if (!user) return res.send("Affiliate not found.");

  db.prepare("UPDATE users SET approved = 1, denied = 0 WHERE discount_code = ?").run(code);

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: "VizelsTweaks Affiliate Application Approved",
    text: `
Hey ${user.first_name},

Your VizelsTweaks affiliate application has been approved!

Login here:
${siteUrl(req)}/login.html

Your Discount Code: ${user.discount_code}
Your Referral Link: ${siteUrl(req)}/?ref=${user.discount_code}
    `
  });

  res.send(`Affiliate ${code} approved and email sent.`);
});

app.get("/admin/deny/:code", async (req, res) => {
  if (!isAdmin(req)) return res.send("Not allowed.");

  const code = cleanAffiliateCode(req.params.code);
  const user = db.prepare("SELECT * FROM users WHERE discount_code = ?").get(code);

  if (!user) return res.send("Affiliate not found.");

  db.prepare("UPDATE users SET approved = 0, denied = 1 WHERE discount_code = ?").run(code);

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: "VizelsTweaks Affiliate Application Update",
    text: `
Hey ${user.first_name},

Thanks for applying to the VizelsTweaks affiliate program.

Your application was not approved at this time.
    `
  });

  res.send(`Affiliate ${code} denied and email sent.`);
});

app.get("/admin/users", (req, res) => {
  if (!isAdmin(req)) return res.send("Not allowed.");

  const users = db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();

  const rows = users.map(user => `
    <div class="admin-user">
      <strong>${user.first_name} ${user.last_name}</strong>
      <p>Email: ${user.email}</p>
      <p>Discord: ${user.discord_username}</p>
      <p>Code: ${user.discount_code}</p>
      <p>Clicks: ${user.clicks} | Sales: ${user.sales} | Commission: $${Number(user.commission).toFixed(2)}</p>
      <p>Verified: ${user.verified ? "Yes" : "No"} | Approved: ${user.approved ? "Yes" : "No"} | Denied: ${user.denied ? "Yes" : "No"}</p>
      <a href="/admin/approve/${user.discount_code}?key=${process.env.ADMIN_KEY}">Approve</a>
      |
      <a href="/admin/deny/${user.discount_code}?key=${process.env.ADMIN_KEY}">Deny</a>
    </div>
  `).join("");

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Admin Users</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="page">
    <div class="card">
      <div class="badge">ADMIN PANEL</div>
      <h1>Affiliate Users</h1>
      <div class="info-box">
        ${rows || "No users yet."}
      </div>
    </div>
  </div>
</body>
</html>
  `);
});

app.get("/admin/clicks", (req, res) => {
  if (!isAdmin(req)) return res.send("Not allowed.");

  const clicks = db.prepare("SELECT * FROM clicks ORDER BY created_at DESC LIMIT 100").all();

  const rows = clicks.map(click => `
    <div class="step">
      <strong>${click.discount_code}</strong><br>
      IP: ${click.ip}<br>
      Time: ${click.created_at}
    </div>
  `).join("");

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Affiliate Clicks</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="page">
    <div class="card">
      <div class="badge">CLICK TRACKING</div>
      <h1>Recent Clicks</h1>
      <div class="info-box">${rows || "No clicks yet."}</div>
    </div>
  </div>
</body>
</html>
  `);
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
app.post("/purchase", (req, res) => {
  try {
    const amount = Number(req.body.amount) || 0;

    const ref = req.cookies?.affiliate_ref;

    if (ref) {
      const user = db.prepare("SELECT * FROM users WHERE discount_code = ? AND approved = 1").get(ref);

      if (user) {
        const commission = amount * 0.30; // 30%

        db.prepare(`
          UPDATE users 
          SET sales = sales + 1,
              commission = commission + ?
          WHERE discount_code = ?
        `).run(commission, ref);
      }
    }

    res.send("Purchase recorded");
  } catch (err) {
    console.error(err);
    res.send("Error recording purchase");
  }
});
