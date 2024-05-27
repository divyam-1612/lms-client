const User = require("../models/User");
const mailSender = require("../utils/mailSender")
const bcrypt = require("bcrypt")
const crypto = require('crypto');

// Link for Reset Password
exports.resetPasswordToken = async(req, res) => {    
    
    try{
        // get email from body
    const email = req.body.email

    //email validation
    const user = await User.findOne({email: email})
    if(!user){
        res.json({
            success: false,
            message: "user does not exist",
        })
    }

    // generate token
    const token = crypto.randomUUID();

    // update user by adding token and expiration time
    const updatedDetails = await User.findOneAndUpdate(
                                        {email: email},
                                        {
                                            token: token,
                                            resetPasswordExpires: Date.now() + 5*60*1000,
                                        },
                                        {new: true});

    // create an url
    const url = `http://localhost:3000/update-password/${token}`

    // send mail
    await mailSender(email , "Reset Your Password" , `Password Reset Link: ${url}`);

    // return response
    return res.json({
        success: true,
        message: "email send successfully to reset your password"
    })
    }
    catch(error){
        console.log(error)
        return res.json({
            success: false,
            message: "error in sending link to reset your password"
        })
    }
}

// Reset Password in UI
exports.resetPassword = async(req,res) => {
    try{    
        //data fetch
        const {token , password, confirmPassword} = req.body

        // validations
        if(password !== confirmPassword){
            return res.json({
                success: false,
                message: "password not matching"
            })
        }

        // get user details from db token
        const userDetails =  await User.findOne({token: token})
        if(!userDetails){
            return res.json({
                success: false,
                message: 'token is invalid'
            })
        }

        

        // token time check
        if(userDetails.resetPasswordExpires < Date.now()){
            return res.json({
                success: false,
                message: "token expired"
            })
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password , 10)

        // Password update
        await User.findOneAndUpdate({token: token} , {password: hashedPassword} , {new: true})
        return res.json({
            success: true,
            message: "pasword resetted successfully"
        })

    }
    catch(error){
        console.log(error)
        return res.json({
            success: false,
            message: "error in resetting the password"
        })
    }
}