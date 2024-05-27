const express = require('express')
const router = express.Router()

const { login, signUp, sendOTP, changePassword} = require("../controllers/Auth")

const {resetPassword, resetPasswordToken} = require("../controllers/ResetPassword")

const {auth, isStudent, isAdmin, isInstructor} = require("../middlewares/auth")


router.post("/login", login)

router.post("/signup", signUp)

router.post("/sendotp", sendOTP)

router.post("/changepassword", auth, changePassword)

router.post("/reset-password-token", resetPasswordToken)
router.post("/reset-password", resetPassword)

module.exports = router;