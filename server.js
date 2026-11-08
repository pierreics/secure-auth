const express = require("express");
const session = require("express-session");
const filestore = require("session-file-store")(session);
const bcrypt = require("bcrypt");
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    store: new filestore({
      path: "./sessions",
      retires: 0,
    }),
    secret: process.env.SECRET_KEY || "chiave_provvisoria",
    saveUninitialized: false,
    resave: false,
  }),
);

const fintoDB = [];
const admin = async () => {
  const hash = await bcrypt.hash("Password123!", 10);
  fintoDB.push({
    username: "admin",
    password: hash,
    role: "admin",
    secret: "",
  });
};
admin();

let ghost = "";
(async () => {
  ghost = await bcrypt.hash("dummy_password", 10);
})();

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
    fintoDB.push({
      username: username,
      password: hash,
      role: "user",
      secret: "",
    });
    res.send("Registrazione effettuata con successo");
  } catch (err) {
    res.send("Errore nell'encrypting della password");
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  try {
    const utentetrovato = fintoDB.find(
      (utente) => utente.username === username,
    );
    if (!utentetrovato) {
      await bcrypt.compare(password, ghost);
      return res.send("Username o password errati");
    }
    const passwordtrovata = await bcrypt.compare(
      password,
      utentetrovato.password,
    );
    if (passwordtrovata) {
      req.session.utenteloggato = true;
      req.session.role = utentetrovato.role;
      req.session.username = utentetrovato.username;
      if (req.session.role === "admin") {
        res.redirect("/admin");
      } else {
        res.redirect("/user");
      }
    } else {
      res.send("Username o password errati");
    }
  } catch (err) {
    console.log("\n\n\n\n\nErrore nella comparazione delle password");
  }
});

app.get("/admin", (req, res) => {
  if (req.session.role === "admin") {
    res.sendFile(__dirname + "/views/admin.html");
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
      const utente = fintoDB.find(
        (cercautente) => cercautente.username === req.session.username,
      );
      if (!utente) {
        return req.session.destroy(() => {
          res.send("Utente non trovato nel db, rifai il login");
        });
      }
      const esito = await bcrypt.compare(oldpassword, utente.password);
      if (esito) {
        if (newpassword1 === newpassword2) {
          utente.password = await bcrypt.hash(newpassword1, 10);
          res.send("Password cambiata");
        } else {
          res.send("Le due nuove password non corrispondono");
        }
      } else {
        res.send("Password non corretta");
      }
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
    const utente = fintoDB.find(
      (user) => user.username === req.session.username,
    );
    if (!utente)
      return req.session.destroy(() =>
        res.send("Utente non trovato, rifai login."),
      );
    if (utente.secret === "") {
      res.send("L'utente non ha ancora inserito alcun segreto");
    } else {
      res.send(`segreto : ${utente.secret}`);
    }
  })
  .post((req, res) => {
    if (!req.session.utenteloggato) {
      return res.redirect("/");
    }
    let segreto = req.body.secret;
    const utente = fintoDB.find(
      (user) => user.username === req.session.username,
    );
    utente.secret = segreto;
    res.redirect("/vault");
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
      const password = req.body.password;
      const utente = fintoDB.find(
        (user) => user.username === req.session.username,
      );
      if (!utente)
        return req.session.destroy(() =>
          res.send("Utente non trovato, rifai login."),
        );
      const indice = fintoDB.findIndex(
        (user) => user.username === req.session.username,
      );
      const esito = await bcrypt.compare(password, utente.password);
      if (!esito) {
        res.send("Password non valida");
      } else {
        fintoDB.splice(indice, 1);
        req.session.destroy();
        res.send("Account eliminato con successo");
      }
    } catch (err) {
      res.send("errore interno");
    }
  });

app.listen(3000, () => {
  console.log("Server attivo sulla porta 3000");
});
