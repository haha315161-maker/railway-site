require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const { csrfSync } = require("csrf-sync");

const app = express();

const PORT =
  Number(process.env.PORT) || 3000;

const IS_PRODUCTION =
  process.env.NODE_ENV === "production";

// ======================================================
// ENV KONTROLÜ
// ======================================================

if (!process.env.SESSION_SECRET) {
  throw new Error(
    "SESSION_SECRET ortam değişkeni tanımlı olmalı."
  );
}

// ======================================================
// DATABASE
// ======================================================

const databasePath =
  process.env.DATABASE_PATH ||
  path.join(__dirname, "database.db");

// Railway Volume gibi harici bir klasör kullanılıyorsa klasörü oluştur.
fs.mkdirSync(path.dirname(databasePath), { recursive: true });

const db = new Database(databasePath);

db.pragma("journal_mode = WAL");

db.prepare(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER DEFAULT 0,
    used INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS support_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sender TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// ======================================================
// EXPRESS
// ======================================================

app.disable("x-powered-by");

app.set(
  "trust proxy",
  IS_PRODUCTION ? 1 : 0
);

// ======================================================
// HELMET
// ======================================================

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

// ======================================================
// BODY LIMIT
// ======================================================

app.use(
  express.json({
    limit: "10kb"
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "10kb"
  })
);

// ======================================================
// SESSION
// ======================================================

app.use(
  session({
    name: "session",

    secret: process.env.SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax",
      maxAge:
        1000 *
        60 *
        60 *
        24
    }
  })
);

// ======================================================
// CSRF
// ======================================================

const {
  csrfSynchronisedProtection,
  generateToken
} = csrfSync({
  ignoredMethods: [
    "GET",
    "HEAD",
    "OPTIONS"
  ],

  getTokenFromRequest: (req) => {
    return req.headers["x-csrf-token"];
  },

  getTokenFromState: (req) => {
    return req.session.csrfToken;
  },

  storeTokenInState: (req, token) => {
    req.session.csrfToken = token;
  },

  size: 128
});

// ======================================================
// CSRF TOKEN ENDPOINT
// ======================================================

app.get(
  "/api/csrf-token",
  (req, res) => {

    try {

      // Var olan token varsa onu kullanır.
      // Yoksa yeni token oluşturur.
      const csrfToken =
        generateToken(req);

      // Token session'a yazıldıktan sonra
      // session'ın kesin olarak kaydedilmesini bekle.
      req.session.save(
        (error) => {

          if (error) {

            console.error(
              "CSRF SESSION SAVE ERROR:",
              error
            );

            return res.status(500).json({
              success: false,
              message:
                "CSRF oturumu kaydedilemedi."
            });

          }

          return res.json({
            success: true,
            csrfToken
          });

        }
      );

    } catch (error) {

      console.error(
        "CSRF TOKEN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "CSRF token oluşturulamadı."
      });

    }

  }
);

// ======================================================
// RATE LIMIT
// ======================================================

const loginLimiter =
  rateLimit({

    windowMs:
      15 * 60 * 1000,

    limit: 10,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
      success: false,
      message:
        "Çok fazla giriş denemesi yaptın. 15 dakika sonra tekrar dene."
    }

  });

const registerLimiter =
  rateLimit({

    windowMs:
      15 * 60 * 1000,

    limit: 5,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
      success: false,
      message:
        "Çok fazla kayıt isteği gönderildi."
    }

  });

const forgotLimiter =
  rateLimit({

    windowMs:
      15 * 60 * 1000,

    limit: 3,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
      success: false,
      message:
        "Çok fazla şifre sıfırlama isteği gönderildi."
    }

  });

const resetLimiter =
  rateLimit({

    windowMs:
      15 * 60 * 1000,

    limit: 10,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
      success: false,
      message:
        "Çok fazla işlem yapıldı. Daha sonra tekrar dene."
    }

  });

// ======================================================
// STATIC
// ======================================================

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

// ======================================================
// MAIL
// ======================================================

const transporter =
  nodemailer.createTransport({

    service: "gmail",

    auth: {
      user:
        process.env.EMAIL_USER,

      pass:
        process.env.EMAIL_PASS
    }

  });

// ======================================================
// INPUT VALIDATION
// ======================================================

function cleanEmail(email) {

  if (
    typeof email !== "string"
  ) {
    return null;
  }

  email =
    email
      .trim()
      .toLowerCase();

  if (
    email.length > 254
  ) {
    return null;
  }

  const emailRegex =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (
    !emailRegex.test(email)
  ) {
    return null;
  }

  return email;
}

function cleanUsername(username) {

  if (
    typeof username !== "string"
  ) {
    return null;
  }

  username =
    username.trim();

  if (
    username.length < 3 ||
    username.length > 30
  ) {
    return null;
  }

  if (
    !/^[a-zA-Z0-9_.-]+$/.test(
      username
    )
  ) {
    return null;
  }

  return username;
}

function cleanPassword(password) {

  if (
    typeof password !== "string"
  ) {
    return null;
  }

  if (
    password.length < 6 ||
    password.length > 128
  ) {
    return null;
  }

  return password;
}

// ======================================================
// AUTH MIDDLEWARE
// ======================================================

function authRequired(
  req,
  res,
  next
) {

  if (!req.session.userId) {

    return res.status(401).json({
      success: false,
      message:
        "Giriş yapmalısın."
    });

  }

  next();
}

// ======================================================
// REGISTER
// ======================================================

app.post(
  "/api/register",

  registerLimiter,

  csrfSynchronisedProtection,

  async (req, res) => {

    try {

      const username =
        cleanUsername(
          req.body.username
        );

      const email =
        cleanEmail(
          req.body.email
        );

      const password =
        cleanPassword(
          req.body.password
        );

      if (
        !username ||
        !email ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Bilgileri doğru şekilde doldur."
        });

      }

      const existingUser =
        db.prepare(`
          SELECT id
          FROM users
          WHERE username = ?
             OR email = ?
        `).get(
          username,
          email
        );

      if (existingUser) {

        return res.status(409).json({
          success: false,
          message:
            "Bu kullanıcı adı veya e-posta zaten kayıtlı."
        });

      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        db.prepare(`
          INSERT INTO users
          (
            username,
            email,
            password
          )
          VALUES (?, ?, ?)
        `).run(
          username,
          email,
          hashedPassword
        );

      req.session.regenerate(
        (error) => {

          if (error) {

            console.error(error);

            return res.status(500).json({
              success: false,
              message:
                "Oturum oluşturulamadı."
            });

          }

          req.session.userId =
            result.lastInsertRowid;

          // Yeni session oluşturulduğu için
          // yeni CSRF token oluştur.
          const csrfToken =
            generateToken(req);

          req.session.save(
            (saveError) => {

              if (saveError) {

                console.error(
                  saveError
                );

                return res.status(500).json({
                  success: false,
                  message:
                    "Oturum kaydedilemedi."
                });

              }

              res.json({
                success: true,
                redirect:
                  "/profile.html",
                csrfRefresh: true,
                csrfToken
              });

            }
          );

        }
      );

    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Sunucu hatası."
      });

    }

  }
);

// ======================================================
// LOGIN
// ======================================================

app.post(
  "/api/login",

  loginLimiter,

  csrfSynchronisedProtection,

  async (req, res) => {

    try {

      const email =
        cleanEmail(
          req.body.email
        );

      const password =
        cleanPassword(
          req.body.password
        );

      if (
        !email ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "E-posta veya şifre hatalı."
        });

      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(email);

      if (!user) {

        return res.status(401).json({
          success: false,
          message:
            "E-posta veya şifre yanlış."
        });

      }

      const passwordCorrect =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!passwordCorrect) {

        return res.status(401).json({
          success: false,
          message:
            "E-posta veya şifre yanlış."
        });

      }

      req.session.regenerate(
        (error) => {

          if (error) {

            console.error(error);

            return res.status(500).json({
              success: false,
              message:
                "Oturum oluşturulamadı."
            });

          }

          req.session.userId =
            user.id;

          // Session regenerate edildiği için
          // yeni CSRF token oluştur.
          const csrfToken =
            generateToken(req);

          req.session.save(
            (saveError) => {

              if (saveError) {

                console.error(
                  saveError
                );

                return res.status(500).json({
                  success: false,
                  message:
                    "Oturum kaydedilemedi."
                });

              }

              res.json({
                success: true,
                redirect:
                  "/profile.html",
                csrfRefresh: true,
                csrfToken
              });

            }
          );

        }
      );

    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Sunucu hatası."
      });

    }

  }
);

// ======================================================
// FORGOT PASSWORD
// ======================================================

app.post(
  "/api/forgot-password",

  forgotLimiter,

  csrfSynchronisedProtection,

  async (req, res) => {

    try {

      const email =
        cleanEmail(
          req.body.email
        );

      if (!email) {

        return res.status(400).json({
          success: false,
          message:
            "Geçerli bir e-posta gir."
        });

      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(email);

      const genericResponse = {
        success: true,
        message:
          "Eğer bu e-posta kayıtlıysa kod gönderildi.",
        redirect:
          "/reset-password.html"
      };

      if (!user) {

        return res.json(
          genericResponse
        );

      }

      db.prepare(`
        UPDATE password_resets
        SET used = 1
        WHERE user_id = ?
          AND used = 0
      `).run(
        user.id
      );

      const code =
        crypto
          .randomInt(
            100000,
            1000000
          )
          .toString();

      const codeHash =
        await bcrypt.hash(
          code,
          10
        );

      const expiresAt =
        Date.now() +
        10 * 60 * 1000;

      db.prepare(`
        INSERT INTO password_resets
        (
          user_id,
          code_hash,
          expires_at,
          attempts,
          used,
          created_at
        )
        VALUES (?, ?, ?, 0, 0, ?)
      `).run(
        user.id,
        codeHash,
        expiresAt,
        Date.now()
      );

      await transporter.sendMail({

        from:
          `"Kişisel Web Sitem" <${process.env.EMAIL_USER}>`,

        to:
          user.email,

        subject:
          "Şifre Sıfırlama Kodun",

        text:
          `Şifre sıfırlama kodun: ${code}. Bu kod 10 dakika geçerlidir.`,

        html: `
          <div style="
            font-family:Arial,sans-serif;
            max-width:600px;
            margin:auto;
            padding:30px;
            background:#111114;
            color:white;
            border-radius:15px;
          ">

            <h1>Şifre Sıfırlama</h1>

            <p>
              Şifreni değiştirmek için
              aşağıdaki kodu kullan:
            </p>

            <div style="
              font-size:38px;
              font-weight:bold;
              letter-spacing:10px;
              color:#a855f7;
              margin:30px 0;
            ">
              ${code}
            </div>

            <p>
              Bu kod
              <strong>10 dakika</strong>
              geçerlidir.
            </p>

            <p style="color:#999">
              Bu isteği sen yapmadıysan
              e-postayı görmezden gelebilirsin.
            </p>

          </div>
        `

      });

      req.session.resetEmail =
        email;

      req.session.save(
        (saveError) => {

          if (saveError) {

            console.error(
              "RESET SESSION SAVE ERROR:",
              saveError
            );

            return res.status(500).json({
              success: false,
              message:
                "Oturum kaydedilemedi."
            });

          }

          res.json(
            genericResponse
          );

        }
      );

    } catch (error) {

      console.error(
        "MAIL ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "E-posta gönderilemedi."
      });

    }

  }
);

// ======================================================
// VERIFY RESET CODE
// ======================================================

app.post(
  "/api/verify-reset-code",

  resetLimiter,

  csrfSynchronisedProtection,

  async (req, res) => {

    try {

      const code =
        typeof req.body.code === "string"
          ? req.body.code.trim()
          : "";

      if (
        !req.session.resetEmail
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Önce şifre sıfırlama isteği oluştur."
        });

      }

      if (
        !/^\d{6}$/.test(code)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "6 haneli kodu gir."
        });

      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          req.session.resetEmail
        );

      if (!user) {

        return res.status(400).json({
          success: false,
          message:
            "Geçersiz istek."
        });

      }

      const reset =
        db.prepare(`
          SELECT *
          FROM password_resets
          WHERE user_id = ?
            AND used = 0
          ORDER BY id DESC
          LIMIT 1
        `).get(
          user.id
        );

      if (!reset) {

        return res.status(400).json({
          success: false,
          message:
            "Geçerli kod bulunamadı."
        });

      }

      if (
        Date.now() >
        reset.expires_at
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Kodun süresi dolmuş."
        });

      }

      if (
        reset.attempts >= 5
      ) {

        return res.status(429).json({
          success: false,
          message:
            "Çok fazla hatalı deneme yapıldı. Yeni kod iste."
        });

      }

      const correct =
        await bcrypt.compare(
          code,
          reset.code_hash
        );

      if (!correct) {

        db.prepare(`
          UPDATE password_resets
          SET attempts =
            attempts + 1
          WHERE id = ?
        `).run(
          reset.id
        );

        return res.status(400).json({
          success: false,
          message:
            "Kod yanlış."
        });

      }

      req.session.resetVerified =
        true;

      req.session.resetId =
        reset.id;

      req.session.save(
        (saveError) => {

          if (saveError) {

            console.error(
              saveError
            );

            return res.status(500).json({
              success: false,
              message:
                "Oturum kaydedilemedi."
            });

          }

          res.json({
            success: true,
            message:
              "Kod doğrulandı."
          });

        }
      );

    } catch (error) {

      console.error(
        "VERIFY RESET ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Sunucu hatası."
      });

    }

  }
);

// ======================================================
// RESET PASSWORD
// ======================================================

app.post(
  "/api/reset-password",

  resetLimiter,

  csrfSynchronisedProtection,

  async (req, res) => {

    try {

      const password =
        cleanPassword(
          req.body.password
        );

      if (
        !req.session.resetEmail ||
        !req.session.resetVerified ||
        !req.session.resetId
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Önce e-posta kodunu doğrula."
        });

      }

      if (!password) {

        return res.status(400).json({
          success: false,
          message:
            "Şifre 6-128 karakter arasında olmalı."
        });

      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          req.session.resetEmail
        );

      if (!user) {

        return res.status(400).json({
          success: false,
          message:
            "Kullanıcı bulunamadı."
        });

      }

      const reset =
        db.prepare(`
          SELECT *
          FROM password_resets
          WHERE id = ?
            AND user_id = ?
            AND used = 0
        `).get(
          req.session.resetId,
          user.id
        );

      if (!reset) {

        return res.status(403).json({
          success: false,
          message:
            "Şifre sıfırlama işlemi geçersiz."
        });

      }

      if (
        Date.now() >
        reset.expires_at
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Şifre sıfırlama kodunun süresi dolmuş."
        });

      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const updateUser =
        db.transaction(() => {

          db.prepare(`
            UPDATE users
            SET password = ?
            WHERE id = ?
          `).run(
            hashedPassword,
            user.id
          );

          db.prepare(`
            UPDATE password_resets
            SET used = 1
            WHERE id = ?
          `).run(
            reset.id
          );

        });

      updateUser();

      delete req.session.resetEmail;
      delete req.session.resetVerified;
      delete req.session.resetId;

      req.session.save(
        (saveError) => {

          if (saveError) {

            console.error(
              saveError
            );

            return res.status(500).json({
              success: false,
              message:
                "Oturum kaydedilemedi."
            });

          }

          res.json({
            success: true,
            message:
              "Şifren başarıyla değiştirildi.",
            redirect:
              "/login.html"
          });

        }
      );

    } catch (error) {

      console.error(
        "RESET PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Şifre değiştirilemedi."
      });

    }

  }
);

// ======================================================
// ADMIN AUTH
// ======================================================

function adminRequired(req, res, next) {

  if (!req.session.userId) {

    return res.status(401).json({
      success: false,
      message: "Giriş yapmalısın."
    });

  }

  try {

    const user = db.prepare(`
      SELECT id, email
      FROM users
      WHERE id = ?
    `).get(req.session.userId);

    if (!user) {

      return res.status(401).json({
        success: false,
        message: "Kullanıcı bulunamadı."
      });

    }

    const adminEmail =
      String(process.env.ADMIN_EMAIL || "")
        .trim()
        .toLowerCase();

    const userEmail =
      String(user.email || "")
        .trim()
        .toLowerCase();

    if (
      !adminEmail ||
      userEmail !== adminEmail
    ) {

      console.log(
        "ADMIN RED:",
        {
          userEmail,
          adminEmail
        }
      );

      return res.status(403).json({
        success: false,
        message: "Admin yetkin yok."
      });

    }

    next();

  } catch (error) {

    console.error(
      "ADMIN AUTH ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Admin kontrolü yapılamadı."
    });

  }
}

// ======================================================
// USER SUPPORT - MESAJLARI GETİR
// ======================================================

app.get(
  "/api/support/messages",

  authRequired,

  (req, res) => {

    try {

      const messages =
        db.prepare(`
          SELECT
            id,
            sender,
            message,
            created_at
          FROM support_messages
          WHERE user_id = ?
          ORDER BY
            created_at ASC,
            id ASC
        `).all(
          req.session.userId
        );

      res.json({
        success: true,
        messages
      });

    } catch (error) {

      console.error(
        "USER SUPPORT GET ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Destek mesajları alınamadı."
      });

    }
  }
);


// ======================================================
// USER SUPPORT - MESAJ GÖNDER
// ======================================================

app.post(
  "/api/support/messages",

  authRequired,

  csrfSynchronisedProtection,

  (req, res) => {

    try {

      const message =
        typeof req.body.message === "string"
          ? req.body.message.trim()
          : "";

      if (
        !message ||
        message.length > 2000
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Mesaj 1-2000 karakter arasında olmalı."
        });

      }

      db.prepare(`
        INSERT INTO support_messages
        (
          user_id,
          sender,
          message
        )
        VALUES (?, ?, ?)
      `).run(
        req.session.userId,
        "user",
        message
      );

      res.json({
        success: true,
        message:
          "Mesaj gönderildi."
      });

    } catch (error) {

      console.error(
        "USER SUPPORT POST ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Mesaj gönderilemedi."
      });

    }
  }
);

// ======================================================
// ADMIN SUPPORT - MESAJLARI GETİR
// ======================================================

app.get(
  "/api/admin/support",

  adminRequired,

  (req, res) => {

    try {

      const messages =
        db.prepare(`
          SELECT
            support_messages.id,
            support_messages.user_id,
            support_messages.sender,
            support_messages.message,
            support_messages.created_at,
            users.username,
            users.email
          FROM support_messages

          INNER JOIN users
            ON users.id =
              support_messages.user_id

          ORDER BY
            support_messages.created_at ASC,
            support_messages.id ASC
        `).all();

      res.json({
        success: true,
        messages
      });

    } catch (error) {

      console.error(
        "ADMIN SUPPORT GET ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Destek mesajları alınamadı."
      });

    }

  }
);

// ======================================================
// ADMIN SUPPORT - CEVAP GÖNDER
// ======================================================

app.post(
  "/api/admin/support/reply",

  adminRequired,

  csrfSynchronisedProtection,

  (req, res) => {

    try {

      const userId =
        Number(
          req.body.userId
        );

      const message =
        typeof req.body.message === "string"
          ? req.body.message.trim()
          : "";

      if (
        !Number.isInteger(userId) ||
        userId <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Geçersiz kullanıcı."
        });

      }

      if (
        !message ||
        message.length > 2000
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Mesaj 1-2000 karakter arasında olmalı."
        });

      }

      const user =
        db.prepare(`
          SELECT id
          FROM users
          WHERE id = ?
        `).get(userId);

      if (!user) {

        return res.status(404).json({
          success: false,
          message:
            "Kullanıcı bulunamadı."
        });

      }

      db.prepare(`
        INSERT INTO support_messages
        (
          user_id,
          sender,
          message
        )
        VALUES (?, ?, ?)
      `).run(
        userId,
        "admin",
        message
      );

      res.json({
        success: true,
        message:
          "Cevap gönderildi."
      });

    } catch (error) {

      console.error(
        "ADMIN SUPPORT REPLY ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Cevap gönderilemedi."
      });

    }

  }
);
// ======================================================
// ADMIN CHECK
// ======================================================

app.get(
  "/api/admin/check",

  authRequired,

  (req, res) => {

    try {

      const user =
        db.prepare(`
          SELECT id, email
          FROM users
          WHERE id = ?
        `).get(
          req.session.userId
        );

      if (!user) {

        return res.status(404).json({
          success: false,
          isAdmin: false
        });

      }

      const adminEmail =
        String(
          process.env.ADMIN_EMAIL || ""
        )
          .trim()
          .toLowerCase();

      const isAdmin =
        !!adminEmail &&
        user.email.trim().toLowerCase() ===
        adminEmail;

      return res.json({
        success: true,
        isAdmin
      });

    } catch (error) {

      console.error(
        "ADMIN CHECK ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        isAdmin: false
      });

    }

  }
);

// ======================================================
// CURRENT USER
// ======================================================

app.get(
  "/api/me",

  authRequired,

  (req, res) => {

    const user =
      db.prepare(`
        SELECT
          id,
          username,
          email,
          created_at
        FROM users
        WHERE id = ?
      `).get(
        req.session.userId
      );

    if (!user) {

      return res.status(404).json({
        success: false,
        message:
          "Kullanıcı bulunamadı."
      });

    }

    const adminEmail =
      String(
        process.env.ADMIN_EMAIL || ""
      )
        .trim()
        .toLowerCase();

    const isAdmin =
      Boolean(
        adminEmail &&
        user.email.trim().toLowerCase() ===
        adminEmail
      );

    res.json({
      success: true,

      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at,
        isAdmin
      }
    });

  }
);

// ======================================================
// LOGOUT
// ======================================================

app.post(
  "/api/logout",

  csrfSynchronisedProtection,

  (req, res) => {

    req.session.destroy(
      (error) => {

        if (error) {

          console.error(error);

          return res.status(500).json({
            success: false,
            message:
              "Çıkış yapılamadı."
          });

        }

        res.clearCookie(
          "session",
          {
            httpOnly: true,
            sameSite: "lax",
            secure: IS_PRODUCTION,
            path: "/"
          }
        );

        res.json({
          success: true,
          redirect: "/"
        });

      }
    );

  }
);
// ======================================================
// ADMIN PAGE
// ======================================================

app.get(
  "/admin.html",
  (req, res) => {

    if (!req.session.userId) {
      return res.redirect("/login.html");
    }

    const user =
      db.prepare(`
        SELECT id, email
        FROM users
        WHERE id = ?
      `).get(req.session.userId);

    if (!user) {
      return res.redirect("/login.html");
    }

    const adminEmail =
      String(process.env.ADMIN_EMAIL || "")
        .trim()
        .toLowerCase();

    if (
      !adminEmail ||
      user.email.trim().toLowerCase() !== adminEmail
    ) {
      return res.status(403).send(`
        <!DOCTYPE html>
        <html lang="tr">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Yetkisiz Erişim</title>
          <style>
            body {
              margin: 0;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              background: #0f0f12;
              color: white;
              font-family: Arial, sans-serif;
              text-align: center;
            }

            .box {
              padding: 40px;
              border-radius: 20px;
              background: #18181d;
              box-shadow: 0 20px 60px rgba(0,0,0,.4);
            }

            a {
              display: inline-block;
              margin-top: 20px;
              color: #a855f7;
              text-decoration: none;
            }
          </style>
        </head>

        <body>
          <div class="box">
            <h1>403</h1>
            <p>Bu sayfaya erişim yetkin yok.</p>
            <a href="/">Ana sayfaya dön</a>
          </div>
        </body>
        </html>
      `);
    }

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "admin.html"
      )
    );
  }
);

// ======================================================
// PROFILE PAGE
// ======================================================

app.get(
  "/profile.html",
  (req, res) => {

    if (
      !req.session.userId
    ) {

      return res.redirect(
        "/login.html"
      );

    }

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "profile.html"
      )
    );

  }
);

// ======================================================
// HEALTH CHECK
// ======================================================

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "ok"
  });
});

// ======================================================
// 404
// ======================================================

app.use(
  (req, res) => {

    if (
      req.path.startsWith(
        "/api/"
      )
    ) {

      return res.status(404).json({
        success: false,
        message:
          "API endpoint bulunamadı."
      });

    }

    res.status(404).send(
      "Sayfa bulunamadı."
    );

  }
);

// ======================================================
// ERROR HANDLER
// ======================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "SERVER ERROR:",
      error
    );

    console.error(
      "STACK:",
      error?.stack
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    const status =
      error?.code ===
      "EBADCSRFTOKEN"
        ? 403
        : 500;

    res.status(status).json({
      success: false,

      message:
        error?.message ||
        "Beklenmeyen bir sunucu hatası oluştu.",

      error:
        error?.code ||
        null
    });

  }
);

// ======================================================
// START
// ======================================================

app.listen(
  PORT,
  () => {

    console.log("");

    console.log(
      "======================================"
    );

    console.log(
      "       GÜVENLİ SUNUCU BAŞLATILDI"
    );

    console.log(
      "======================================"
    );

    console.log(
      `       http://localhost:${PORT}`
    );

    console.log(
      "======================================"
    );

    console.log("");

  }
);
