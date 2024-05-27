const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = require('otp-generator')
const Profile = require("../models/Profile")
const jwt = require("jsonwebtoken")
require("dotenv").config();
const mailSender = require("../utils/mailSender")
const bcrypt = require("bcrypt")
const { passwordUpdated } = require("../mail/templates/passwordUpdated")

// send OTP

exports.sendOTP = async (req, res) => {
  try {
    // fetch email from req.body
    const { email } = req.body;

    //check if user already exists
    const checkUserPresent = await User.findOne({ email });

    // if user exists
    if (checkUserPresent) {
      return res.status(401).json({
        success: false,
        message: "user already registered",
      });
    }

    // generate otp
    var otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
    })
    console.log("OTP generated: ", otp);

    // check uniqueness of otp
    let result = await OTP.findOne({otp: otp});

    while(result){
        otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false,
        }) 
        result = await OTP.findOne({otp: otp})
    }

    // create an entry for otp
    const otpPayload = {email , otp}

    const otpBody = await OTP.create(otpPayload);
    console.log(otpBody)
    return res.json({
        success: true,
        message: 'otp sent',
        otpBody
    })

  } catch (error) {
    console.log(error)
    return res.json({
        success: false,
        message: 'Error in sending OTP'
    })
  }
};

//  signup

exports.signUp = async(req,res) => {

    try{
         // data fetch from body
    const {
        firstName,
        lastName,
        email,
        password,
        confirmPassword,
        accountType,
        contactNumber,
        otp
    } = req.body;

    console.log("email******************************************** ", accountType)

    if(!firstName || !lastName || !email || !password || !confirmPassword || !otp){
        return res.json({
            success: false,
            message: "all fields are required"
        })
    }

    // password match
    if(password !== confirmPassword){
        return res.json({
            success: false,
            message: "passwords are not same"
        })
    }

    // check if user already exists
    const existingUser = await User.findOne({email});
    if(existingUser){
        return res.json({
            success: false,
            message: "user already exists"
        })
    }

    // find most recent otp
    const recentOtp = await OTP.find({email}).sort({createdAt:-1}).limit(1);
    // validate otp
    if(recentOtp.length == 0){
        return res.json({
            success: false,
            message: "otp not found"
        })
    }
    
    else if(otp !== recentOtp[0].otp){
        return res.json({
            success: false,
            message: "invalid otp"
        })
    }
    console.log(otp)
    console.log(recentOtp[0].otp)
    // hash passwords
    const hashedPassword = await bcrypt.hash(password , 10);

    const profileDetails = await Profile.create({   
        gender: null,
        dateOfBirth: null,
        about: null,
        contactNumber: null,
    })
    
    // create entry in DB
    const user = await User.create({
        firstName,
        lastName,
        email,
        password: hashedPassword,
        contactNumber,
        accountType,
        additionalDetails: profileDetails._id,
        image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`
    })

    console.log("user = ", user)
    
    return res.json({
        success: true,
        message: 'user registered successfully',
        user,
    })

    } 
    catch(error){
        console.log(error)
        return res.json({
            success: false,
            message: 'user cannot be registered'
        })
    }
}

// login
exports.login = async(req,res) => {
    try{

        // get data
        const {email , password} = req.body

        //validation
        if(!email || !password){
            return res.json({
                success: false,
                message: 'all fields are required'
            })
        }

        // check if user already exists
        const user = await User.findOne({email})
        console.log(user)
        if(!user){
            return res.json({
                success: false,
                message: 'you have to signup first'
            })
        }

        // generate jwt tokens after matching passwords
        if(await bcrypt.compare(password , user.password)){
            const payload = {
                email: user.email,
                id: user._id,
                accountType: user.accountType
            }

            const token = jwt.sign(payload , process.env.JWT_SECRET , {
                expiresIn: "2h",
            })
            user.token = token;
            user.password = undefined;

            const options = {
                expires: new Date(Date.now() + 3*24*60*60*60*100),
                httpOnly: true,
            }

            // create cookie and send response
            res.cookie("token" , token , options).status(200).json({
                success: true,
                token,
                user,
                message: "logged in successfully",
            })
        }     
        else{
            return res.json({
                success: false,
                message: "password is incorrect"
            })
        }  
    }
    catch(error){
        return res.json({
            success: false,
            message: "login failure",
        })
    }
}

// change password
exports.changePassword = async (req, res) => {
    try {
      // Get user data from req.user
      const userDetails = await User.findById(req.user.id)
  
      // Get old password, new password, and confirm new password from req.body
      const { oldPassword, newPassword } = req.body
  
      // Validate old password
      const isPasswordMatch = await bcrypt.compare(
        oldPassword,
        userDetails.password
      )
      if (!isPasswordMatch) {
        // If old password does not match, return a 401 (Unauthorized) error
        return res
          .status(401)
          .json({ success: false, message: "The password is incorrect" })
      }
  
      // Update password
      const encryptedPassword = await bcrypt.hash(newPassword, 10)
      const updatedUserDetails = await User.findByIdAndUpdate(
        req.user.id,
        { password: encryptedPassword },
        { new: true }
      )
  
      // Send notification email
      try {
        const emailResponse = await mailSender(
          updatedUserDetails.email,
          "Password for your account has been updated",
          passwordUpdated(
            updatedUserDetails.email,
            `Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`
          )
        )
        console.log("Email sent successfully:", emailResponse.response)
      } catch (error) {
        // If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
        console.error("Error occurred while sending email:", error)
        return res.status(500).json({
          success: false,
          message: "Error occurred while sending email",
          error: error.message,
        })
      }
  
      // Return success response
      return res
        .status(200)
        .json({ success: true, message: "Password updated successfully" })
    } catch (error) {
      // If there's an error updating the password, log the error and return a 500 (Internal Server Error) error
      console.error("Error occurred while updating password:", error)
      return res.status(500).json({
        success: false,
        message: "Error occurred while updating password",
        error: error.message,
      })
    }
  }