const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const { body, validationResult } = require("express-validator");

const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_fallback_secret_key_67890";

const validateResult = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return sendError(res, 400, errors.array()[0].msg);
  }
  next();
}

const registerValidation = [
  body("username")
    .isString().withMessage("Username must be a string")
    .trim()
    .notEmpty().withMessage("Username is required")
    .isLength({ min: 3, max: 30 }).withMessage("Username must be between 3 and 30 characters"),
  body("password")
      .isString().withMessage("Password must be a string")
      .notEmpty().withMessage("Password is required")
    .custom((value) => {
      if (!validaPassword(value)) {
          throw new Error("Passwor does not meet complexity requirement")
      }
      return true;
      }),
  validateResult  
];

const loginValidation =[
  body("username")
    .isString().withMessage("Username must be a string")
    .trim()
    .notEmpty().withMessage("Username is required"),
  body("password")
      .isString().withMessage("Password must be a string")
      .notEmpty().withMessage("Password is required"),
  validateResult  
];

const vaultValidation = [
  body("secret")
    .isString().withMessage("Secret must be a string")
    .notEmpty().withMessage("Secret is required")
    .trim()
    .isLength({ max: 500 }).withMessage("Secret must be under 500 characters"),
  validateResult
]


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

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      error: "Accesso negato, devi effettuare il login"
    });
  }
  next();
}

function sendError(res, statusCode, message, err=null) {
  if (err) {
    console.error("Errore : " ,err.message);
  }
  return res.status(statusCode).json({
    success: false,
    error : message
  })
}

function sendInternalError(res, err) {
  return sendError(res, 500, "Internal Error", err);
}

function generateJWTtoken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    {
      algorithm: "HS256",
      expiresIn: "15m"
    }
  );
}

function requireJWTauth(req, res, next) {
  let token = "";
  if (req.cookies && req.cookies.accessToken) {
    token = accessToken.split(" ")[1];
  }
  else if ( req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) {
    sendError(res, 409, "Invalid token");
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256']
    });
    req.user = decoded;
    next()
  } catch (err) {
    return sendError(res, 401, "invalid Token");
  }
  
}

function generateRefreshToken() {
  return crypto.randomBytes(64).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest(hex);
}

module.exports = {
  validaPassword,
  sendError,
  requireAuth,
  registerValidation,
  loginValidation,
  vaultValidation,
  sendInternalError,
  generateJWTtoken,
  requireJWTauth,
  generateRefreshToken,
  hashToken
};