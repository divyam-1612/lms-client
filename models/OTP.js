const mongoose = require('mongoose');
const mailSender = require('../utils/MailSender');
const emailTemplate = require("../mail/templates/emailVerificationTemplate")

const OTPSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
    },
    otp: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now(),
        expires: 5*50,
    },
})

// a function to send email

async function sendVerificationEmail(email , otp){
    try{
        const mailResponse = await mailSender(email , "Email From Divyam" , emailTemplate(otp));
        console.log("email sent successfully " , mailResponse);
    }
    catch(error){
        console.log("error occured while sending mails: " , error);
        throw error;
    }
}

OTPSchema.pre("save", async function(next)   {
    await sendVerificationEmail(this.email , this.otp);
    next();
})  

module.exports = mongoose.model("OTP" , OTPSchema);
