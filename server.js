const express = require("express");
const session = require("express-session");
const filestore = require("session-file-store")(session);
const bcrypt = require("bcrypt");
const db = require("./database");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const {
  validaPassword,
  sendError,
  requireAuth,
  sendInternalError,
  registerValidation,
  loginValidation,
  vaultValidation,
  generateJWTtoken,
  requireJWTauth,
  generateRefreshToken,
  hashToken,
} = require("./utils");
const app = express();

const REFRESH_TOKEN_MS = 1000 * 60 * 60 * 24 * 7;
const ACCESS_TOKEN_MS = 1000 * 60 * 15;

if (
  (!process.env.SECRET_KEY ||
    !process.env.ADMIN_PASSWORD ||
    !process.env.JWT_SECRET) &&
  process.env.NODE_ENV === "production"
) {
  console.error("FATAL ERROR: Manca SECRET_KEY o ADMIN_PASSWORD o JWT SECRET");
  process.exit(1);
}

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    store: new filestore({
      path: "./sessions",
      retries: 0,
    }),
    secret: process.env.SECRET_KEY || "dev_fallback_secret_key_12345",
    saveUninitialized: false,
    resave: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24,
    },
  }),
);

//Ratelimiting as a protection to brute force attacks
const rateLimiter = rateLimit({
  windowMs: 1000 * 60 * 10,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return sendError(res, 429, "Too many requests, try later");
  },
});

let ghost = "";
(async () => {
  ghost = await bcrypt.hash("dummy_password", 10);
})();

app.post("/api/register", rateLimiter, registerValidation, async (req, res) => {
  const { username, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)`;
    db.run(query, [username, hash, "user", ""], (err) => {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return sendError(res, 409, "Username is already taken");
        } else {
          return sendError(res, 500, "Internal error", err);
        }
      }
      return res.status(201).json({
        success: true,
        message: "Registrazione effettuata con successo",
      });
    });
  } catch (err) {
    return sendError(res, 500, "Internal error", err);
  }
});

app.post("/api/login", rateLimiter, loginValidation, async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, row) => {
      if (err) {
        return sendError(res, 500, "Internal error", err);
      } else if (!row) {
        //Mitigates timing-based user enumeration : even when the user does not exist, we run a dummy bcrypt.compare against a fixed hash so the response time stays constant and does not leak whether the account exists.
        //Generic error message : does not reveal whether the username or the password was wrong to prevent username enumeration.
        await bcrypt.compare(password, ghost);
        return sendError(res, 401, "Username or password are not valid");
      }
      const esito = await bcrypt.compare(password, row.password);
      if (!esito) {
        return sendError(res, 401, "Username or password are not valid");
      } else {
        req.session.regenerate((err) => {
          if (err) {
            return sendInternalError(res, err);
          }
          req.session.userId = row.id;
          req.session.username = row.username;
          req.session.role = row.role;
          return res.status(200).json({
            success: true,
            message: "Login effettuato con successo",
          });
        });
      }
    });
  } catch (err) {
    return sendError(res, 500, "Internal error", err);
  }
});

app.get("/api/users/me", requireAuth, (req, res) => {
  return res.status(200).json({
    success: true,
    data: {
      id: req.session.userId,
      username: req.session.username,
      role: req.session.role,
    },
  });
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return sendError(res, 500, "Internal error", err);
    }
    res.clearCookie("connect.sid");
    return res.status(200).json({
      success: true,
      message: "Logout completato con successo",
    });
  });
});

app.get("/api/adminsecrets", requireAuth, (req, res) => {
  if (req.session.role != "admin") {
    return sendError(res, 409, "Admin area");
  }
  try {
    const query = "SELECT username, secret FROM users";
    db.all(query, [], (err, row) => {
      if (err) {
        return sendError(res, 500, "Internal error", err);
      }
      let secrets = row.map((user) => ({
        user: user.username,
        secret: user.secret,
      }));
      res.status(200).json({
        success: true,
        data: secrets,
      });
    });
  } catch (err) {
    sendError(res, 500, "Internal Error", err);
  }
});

app.post("/api/changepassword", requireAuth, async (req, res) => {
  const { oldpassword, newpassword1, newpassword2 } = req.body;
  if (!oldpassword || !newpassword1 || !newpassword2) {
    return sendError(res, 409, "Missing parameters");
  }
  if (newpassword1 !== newpassword2) {
    return sendError(res, 409, "The 2 passwords do not match");
  }
  if (!validaPassword(newpassword1)) {
    return sendError(res, 409, "The new password is too weak");
  }
  try {
    let query = "SELECT password FROM users WHERE username = ?";
    db.get(query, [req.session.username], async (err, row) => {
      if (err) {
        return sendError(res, 500, "Internal error", err);
      }
      const esito = await bcrypt.compare(oldpassword, row.password);
      if (!esito) {
        return sendError(res, 409, "The password is incorrect");
      }
      query = "UPDATE users SET password = ? WHERE username = ?";
      const password = await bcrypt.hash(newpassword1, 10);
      db.run(query, [password, req.session.username], (err) => {
        if (err) {
          return sendError(res, 500, "Internal error", err);
        }
        return res.status(200).json({
          success: true,
          message: "Password updated",
        });
      });
    });
  } catch (err) {
    return sendError(res, 500, "Internal error", err);
  }
});

app
  .route("/api/vault")
  .get(requireAuth, (req, res) => {
    try {
      const query = "SELECT secret  FROM users WHERE username = ? ";
      db.get(query, req.session.username, (err, row) => {
        if (err) {
          return sendError(res, 500, "Internal Error", err);
        }
        if (!row) {
          return sendError(res, 407, "Session Expired", err);
        }
        return res.status(200).json({
          success: true,
          data: {
            secret: row.secret,
          },
        });
      });
    } catch (err) {
      return sendError(res, 500, "Internal Error", err);
    }
  })
  .post(requireAuth, vaultValidation, (req, res) => {
    const { secret } = req.body;
    try {
      const query = "UPDATE users SET secret = ? WHERE username = ?";
      db.run(query, [secret, req.session.username], (err) => {
        if (err) {
          return sendInternalError(res, err);
        }
        return res.status(200).json({
          success: true,
          message: "Secret updated",
        });
      });
    } catch (err) {
      return sendInternalError(res, err);
    }
  });

app.post("/api/deleteaccount", requireAuth, (req, res) => {
  const { password } = req.body;
  try {
    let query = "SELECT password FROM users WHERE username = ?";
    db.get(query, [req.session.username], async (err, row) => {
      if (err) {
        return sendInternalError(res, err);
      }
      if (!row) {
        return sendError(res, 407, "Authentication expired");
      }
      const esito = await bcrypt.compare(password, row.password);
      if (!esito) {
        return sendError(res, 407, "Password does not match");
      }
      query = "DELETE FROM users  WHERE username = ?";
      db.run(query, [req.session.username], (err) => {
        if (err) {
          return sendInternalError(res, err);
        }
        req.session.destroy(() => {
          res.clearCookie("connect.sid");
          return res.status(200).json({
            success: true,
            message: "Account deleted correctly",
          });
        });
      });
    });
  } catch (err) {
    return sendInternalError(res, err);
  }
});

app.post("/api/jwt/login", rateLimiter, loginValidation, (req, res) => {
  const { username, password } = req.body;
  try {
    let query = "SELECT * FROM users WHERE username = ?";
    db.get(query, [username], async (err, row) => {
      if (err) {
        return sendInternalError(res, err);
      }
      if (!row) {
        await bcrypt.compare(password, ghost);
        return sendError(res, 401, "Username or password are not valid");
      }
      const esito = await bcrypt.compare(password, row.password);
      if (!esito) {
        return sendError(res, 401, "Username or password are not valid");
      }
      const accessToken = generateJWTtoken(row);
      const refreshToken = generateRefreshToken();
      const hashrefreshtoken = hashToken(refreshToken);
      const timestamp = Date.now() + REFRESH_TOKEN_MS;
      query =
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)";
      db.run(query, [row.id, hashrefreshtoken, timestamp], (err) => {
        if (err) {
          return sendInternalError(res, err);
        }
        res.cookie("accessToken", accessToken, {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          maxAge: ACCESS_TOKEN_MS
        });
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          maxAge: REFRESH_TOKEN_MS
        })
        return res.status(200).json({
          success: true,
          message: "Login effettuato con successo",
        });
      });
    });
  } catch (err) {
    return sendInternalError(res, err);
  }
});

app.post("/api/jwt/logout", (req, res) => {
  if (req.cookies.refreshToken) {
    const token = hashToken(req.cookies.refreshToken);
    const query = "DELETE FROM refresh_tokens WHERE token_hash = ?";
    db.run(query, [token], (err) => {
      if (err) {
        return sendInternalError(res, err);
      }
        res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  });
  return res.status(200).json({
    success: true,
    message: "Logout completed",
  });
});
  }
else {
  res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  });
  return res.status(200).json({
    success: true,
    message: "Logout completed",
  });
  }
});

app.get("/api/jwt/me", requireJWTauth, (req, res) => {
  return res.status(200).json({
    success: true,
    data: {
      id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
    },
  });
});

app.get("/api/jwt/vault", requireJWTauth, (req, res) => {
  const query = "SELECT secret FROM users WHERE username = ?";
  db.get(query, [req.user.username], (err, row) => {
    if (err) {
      return sendInternalError(res, err);
    }
    if (!row) {
      return sendError(res, 409, "User not found");
    }
    return res.status(200).json({
      success: true,
      data: {
        secret: row.secret,
      },
    });
  });
});

app.post("/api/jwt/refresh", (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) {
    return sendError(res, 401, "Invalid token");
  }
  const hash_Token = hashToken(refreshToken);
  let query = "SELECT * FROM refresh_tokens WHERE token_hash = ?";
  db.get(query, [hash_Token], (err, tokenRow) => {
    if (err) {
      return sendInternalError(res, err);
    }
    if (!tokenRow) {
      res.clearCookie("refreshToken", {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production"
      });
      res.clearCookie("accessToken", {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production"
      });

      return sendError(res, 401, "Invalid token");
    }
    if (tokenRow.expires_at < Date.now()) {
      db.run("DELETE FROM refresh_tokens WHERE id = ?", [tokenRow.id], (err) => {
        if (err) {
          return sendInternalError(res, err);
        }
        res.clearCookie("refreshToken", {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production"
        });
        res.clearCookie("accessToken", {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production"
        });
        return sendError(res, 401, "Invalid token");
      });
      return;
    }
    query = "SELECT * FROM users WHERE id = ?";
    db.get(query, [tokenRow.user_id], (err, row) => {
      if (err) {
        return sendInternalError(res, err);
      }
      if (!row) {
        res.clearCookie("refreshToken", {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production"
        });
        res.clearCookie("accessToken", {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production"
        });
        return sendError(res, 400, "Invalid token");
      }
      query = "DELETE from refresh_tokens WHERE id = ?";
      db.run(query, [tokenRow.id], (err) => {
        if (err) {
          return sendInternalError(res, err);
        }
        const newaccesstoken = generateJWTtoken(row);
        const newrefreshtoken = generateRefreshToken();
        const hashnewrefreshtoken = hashToken(newrefreshtoken);
        const newexpires_at = Date.now() + REFRESH_TOKEN_MS;
        query = "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
        db.run(query, [row.id, hashnewrefreshtoken, newexpires_at], (err) => {
          if (err) {
            return sendInternalError(res, err);
          }
          res.cookie("accessToken", newaccesstoken, {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production",
            maxAge: ACCESS_TOKEN_MS,
          });
          res.cookie("refreshToken", newrefreshtoken, {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production",
            maxAge: REFRESH_TOKEN_MS
          });
          return res.status(200).json({
            success: true,
            message: "Token successfully updated"
          });
        });
      });
    });
  });
});

app.listen(3000, () => {
  console.log("Server attivo sulla porta 3000");
});
