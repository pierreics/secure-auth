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
  sendError(res, 500, "Internal Error", err);
}

module.exports = {
  validaPassword,
  sendError,
  requireAuth
};