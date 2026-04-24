require("dotenv").config();

const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const db = new Database("affiliates.db");

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret",
  resave: false,
  saveUninitialized: false
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
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
`).run();

try { db.prepare("ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 0").run(); } catch {}
try { db.prepare("ALTER TABLE users ADD COLUMN denied INTEGER DEFAULT 0").run(); } catch {}

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

function isAdmin(req) {
  return req.query.key === process.env.ADMIN_KEY;
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password, discountCode, discordUsername, agreement } = req.body;

    if (!firstName || !lastName || !email || !password || !discountCode || !discordUsername || agreement !== "on") {
      return res.send("Missing info or agreement not checked.");
    }

    const cleanCode = discountCode.toUpperCase().replace(/[^A-Z0-9]/g, "");

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
http://localhost:3000/admin/approve/${user.discount_code}?key=${process.env.ADMIN_KEY}

Deny:
http://localhost:3000/admin/deny/${user.discount_code}?key=${process.env.ADMIN_KEY}
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
      <p class="subtitle">Your email is verified. Your application is now waiting for review.</p>

      <div class="info-box">
        <h2>Status</h2>
        <div class="step"><strong>Email Verified:</strong> Yes</div>
        <div class="step"><strong>Approved:</strong> Not yet</div>
        <div class="step"><strong>Discount Code:</strong> ${user.discount_code}</div>
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
    <div class="card">
      <div class="badge">AFFILIATE DASHBOARD</div>
      <h1>Welcome, ${user.first_name}</h1>
      <p class="subtitle">Your affiliate account is approved and active.</p>

      <div class="grid">
        <div class="info-box">
          <h2>Account</h2>
          <div class="step"><strong>Name:</strong> ${user.first_name} ${user.last_name}</div>
          <div class="step"><strong>Email:</strong> ${user.email}</div>
          <div class="step"><strong>Discord:</strong> ${user.discord_username}</div>
          <div class="step"><strong>Status:</strong> Approved</div>
        </div>

        <div class="info-box">
          <h2>Affiliate Stats</h2>
          <div class="step"><strong>Discount Code:</strong> ${user.discount_code}</div>
          <div class="step"><strong>Referral Link:</strong> http://localhost:3000/?ref=${user.discount_code}</div>
          <div class="step"><strong>Sales:</strong> ${user.sales}</div>
          <div class="step"><strong>Commission:</strong> $${user.commission}</div>
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
});

app.get("/admin/approve/:code", async (req, res) => {
  if (!isAdmin(req)) return res.send("Not allowed.");

  const code = req.params.code.toUpperCase();
  const user = db.prepare("SELECT * FROM users WHERE discount_code = ?").get(code);

  if (!user) return res.send("Affiliate not found.");

  db.prepare(`
    UPDATE users 
    SET approved = 1, denied = 0 
    WHERE discount_code = ?
  `).run(code);

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: "VizelsTweaks Affiliate Application Approved",
    text: `
Hey ${user.first_name},

Your VizelsTweaks affiliate application has been approved!

You can now log in to your dashboard:
http://localhost:3000/login.html

Your Discount Code: ${user.discount_code}

Welcome to the affiliate program.
    `
  });

  res.send(`Affiliate ${code} approved and email sent.`);
});

app.get("/admin/deny/:code", async (req, res) => {
  if (!isAdmin(req)) return res.send("Not allowed.");

  const code = req.params.code.toUpperCase();
  const user = db.prepare("SELECT * FROM users WHERE discount_code = ?").get(code);

  if (!user) return res.send("Affiliate not found.");

  db.prepare(`
    UPDATE users 
    SET approved = 0, denied = 1 
    WHERE discount_code = ?
  `).run(code);

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: "VizelsTweaks Affiliate Application Update",
    text: `
Hey ${user.first_name},

Thanks for applying to the VizelsTweaks affiliate program.

Your application was not approved at this time.

You can contact support if you believe this was a mistake.
    `
  });

  res.send(`Affiliate ${code} denied and email sent.`);
});

app.get("/admin/users", (req, res) => {
  if (!isAdmin(req)) return res.send("Not allowed.");

  const users = db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();

  const rows = users.map(user => `
    <div class="step">
      <strong>${user.first_name} ${user.last_name}</strong><br>
      Email: ${user.email}<br>
      Discord: ${user.discord_username}<br>
      Code: ${user.discount_code}<br>
      Verified: ${user.verified ? "Yes" : "No"}<br>
      Approved: ${user.approved ? "Yes" : "No"}<br>
      Denied: ${user.denied ? "Yes" : "No"}<br><br>
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

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

app.listen(3000, () => {
  console.log("Website running at http://localhost:3000");
});