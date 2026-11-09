const express = require("express");
const session = require("express-session");
const filestore = require("session-file-store")(session);
const bcrypt = require("bcrypt");
const db = require("./database");
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    store: new filestore({
      path: "./sessions",
      retriesz: 0,
    }),
    secret: process.env.SECRET_KEY || "chiave_provvisoria",
    saveUninitialized: false,
    resave: false,
  }),
);

const fintoDB = [];

let ghost = "";
(async () => {
  ghost = await bcrypt.hash("dummy_password", 10);
})();

//Password complexity policy : enforces length and character variety to reduce the risk of weak, easily-guessable passwords
function validaPassword(password) {
  if (
    typeof password !== "string" ||
    password.length < 8 ||
    password.length > 64
  ) {
    return false;
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialchars = /[!@#$%^&*()_+\-=\[\];':"\\\|,.<>\/?]/.test(password);
  return hasLowercase && hasUppercase && hasNumbers && hasSpecialchars;
}

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/views/home.html");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/views/register.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/views/login.html");
});

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  if (!validaPassword(password)) {
    return res.send(
      "Inserire almeno un carattere maiuscolo, minuscolo, numeri e caratteri speciali",
    );
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)`;
    db.run(query, [username, hash, "user", ""], (err) => {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return res.send("Username già occupato");
        } else {
          console.error(err);
          return res.send("Errore nella registrazione");
        }
      }
      res.send("Registrazione effettuata con successo");
    });
  } catch (err) {
    res.send("Errore nell'encrypting della password");
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  try {
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, row) => {
      if (err) {
        console.error(err);
        return res.send("Errore nel database");
      }
      if (!row) {
        //Mitigates timing-based user enumeration : even when the user does not exist, we run a dummy bcrypt.compare against a fixed hash so the response time stays constant and does not leak whether the account exists.
        //Generic error message : does not reveal whether the username or the password was wrong to prevent username enumeration.
        await bcrypt.compare(password, ghost);
        return res.send("Username o password errati");
      }
      const passwordtrovata = await bcrypt.compare(password, row.password);
      if (passwordtrovata) {
        req.session.utenteloggato = true;
        req.session.role = row.role;
        req.session.username = row.username;
        if (req.session.role === "admin") {
          res.redirect("/admin");
        } else {
          res.redirect("/user");
        }
      } else {
        res.send("Username o password errati");
      }
    });
  } catch (err) {
    console.log("\n\n\n\n\nErrore nella comparazione delle password");
    res.send("errore interno");
  }
});

app.get("/admin", (req, res) => {
  // Access control: admin-only area -- checks the user role.
  if (req.session.role === "admin") {
    res.sendFile(__dirname + "/views/admin.html");
  } else {
    res.send("Area riservata agli admin");
  }
});

app.get("/adminsecrets", (req, res) => {
  if (req.session.role === "admin") {
    let html = "<h2>Area riservata admin</h2><ul>";
    query = "SELECT username, secret FROM users";
    db.all(query, [], (err, rows) => {
      for (const u of rows) {
        html += `<li>${u.username} : ${u.secret}<li>`;
      }
    });
    res.send(html);
  } else {
    res.send("Area riservata agli admin");
  }
});

app.get("/user", (req, res) => {
  if (req.session.utenteloggato === true) {
    res.sendFile(__dirname + "/views/user.html");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.send("Errore nella distruzione della sessione");
    } else {
      res.send("Logout effettuato con successo");
    }
  });
});

app
  .route("/changepassword")
  .get((req, res) => {
    if (req.session.utenteloggato === true) {
      res.sendFile(__dirname + "/views/changepassword.html");
    } else {
      res.redirect("/login");
    }
  })
  .post(async (req, res) => {
    // Access control: protected route — requires an authenticated session.
    if (!req.session.utenteloggato) {
      return res.redirect("/login");
    }
    const oldpassword = req.body.oldpassword;
    const newpassword1 = req.body.newpassword1;
    const newpassword2 = req.body.newpassword2;
    if (!validaPassword(newpassword1)) {
      return res.send(
        "Inserire almeno un carattere maiuscolo, minuscolo, numeri e caratteri speciali",
      );
    }
    try {
      if (newpassword1 !== newpassword2) {
        return res.send("Le due password non corrisopondono");
      }
      let query = "SELECT password FROM users WHERE username = ?";
      db.get(query, [req.session.username], async (err, row) => {
        if (err) {
          console.log("Erroe nella ricerca della password nel db");
          return res.send("Errore interno");
        }
        if (!row) {
          return req.session.destroy((err) => {
            res.send("Utente non trovato, rifare il login");
          });
        }
        const esito = await bcrypt.compare(oldpassword, row.password);
        if (!esito) {
          return res.send("Le due password non corrispondono");
        }
        let query = "UPDATE users SET password = ? WHERE username = ?";
        const hash = await bcrypt.hash(newpassword1, 10);
        db.run(query, [hash, req.session.username], (err) => {
          if (err) {
            console.log("Errore nell'aggiornamento della password");
            return res.send("Errore interno");
          }
          return res.send("Aggiornamento fatto");
        });
      });
    } catch (err) {
      res.send("Errore nell'hashing");
    }
  });

app
  .route("/vault")
  .get((req, res) => {
    if (!req.session.utenteloggato) {
      return res.redirect("/");
    }
    const query = "SELECT * FROM users WHERE username = ?";
    db.get(query, [req.session.username], (err, row) => {
      if (!row) {
        return req.session.destroy(() => {
          res.redirect("/");
        });
      } else {
        res.send("Secret : " + row.secret);
      }
    });
  })
  .post((req, res) => {
    if (!req.session.utenteloggato) {
      return res.redirect("/");
    }
    let query = "SELECT * FROM users WHERE username = ?";
    db.get(query, [req.session.username], (err, row) => {
      if (err) {
        console.log("Errore nel database");
        return res.send("Errore interno");
      }
      if (!row) {
        return req.session.destroy(() => {
          res.send("Utente non trovato nel db, rifai il login");
        });
      }
      const segreto = req.body.secret;
      query = "UPDATE users SET secret = ? WHERE username = ?";
      db.run(query, [segreto, req.session.username], (err) => {
        if (err) {
          console.log("Erroe nel caricamento del secret");
          res.send("Errore interno");
        } else {
          return res.redirect("/vault");
        }
      });
    });
  });

app
  .route("/deleteaccount")
  .get((req, res) => {
    if (!req.session.utenteloggato) {
      return res.redirect("/");
    }
    res.sendFile(__dirname + "/views/deleteaccount.html");
  })
  .post(async (req, res) => {
    if (!req.session.utenteloggato) {
      return res.redirect("/");
    }
    try {
      let query = "DELETE FROM users WHERE username = ?";
      db.run(query, [req.session.username], function (err) {
        if (err) {
          console.log("errore nell'eliminazione della password");
          return res.send("Errore interno");
        }
        if (this.changes === 0) {
          return req.session.destroy((err) => {
            if (err) {
              console.log("Errore nella distruzione della sessione");
              return res.send("Errore interno");
            }
            return res.send("Utente non loggato, rifare il login");
          });
        } else {
          res.send("Account eliminato con successo");
        }
      });
    } catch (err) {
      res.send("errore interno");
    }
  });

app.listen(3000, () => {
  console.log("Server attivo sulla porta 3000");
});
