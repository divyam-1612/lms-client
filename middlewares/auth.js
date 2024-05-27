const jwt = require("jsonwebtoken")
require("dotenv").config();
const User = require("../models/User")

// auth
exports.auth = async(req, res, next) => {
    try{

        //extract token
        const token = req.cookies.token || req.body.token || req.header("Authorization").replace("Bearer " , "");
        
        // if token is missing
        if(!token){
            return res.json({
                success: false,
                message: "token is missing"
            })
        }

        // verify the token
        try{
            const decode = jwt.verify(token , process.env.JWT_SECRET)
            console.log(decode)
            req.user = decode
        }
        catch(error){
            return res.json({
                success: false,
                message: 'token is invalid'
            })
        }
        next();
    }
    catch(error){
        return res.json({
            success: false,
            message: "something went wrong while validating the token"
        })
    }
}

//isStudent
exports.isStudent = async(req, res, next) => {
    try{
        if(req.user.accountType != "Student"){
            return res.json({
                success: false,
                message: "this is protected route for students only"
            })
        }
        next()
    }
    catch(error){
        return res.json({
            success: false,
            message: "user role cannot be not verified"
        })
    }
}

// isInstructor
exports.isInstructor = async(req, res, next) => {
    try{
        if(req.user.accountType != "Instructor"){
            return res.json({
                success: false,
                message: "this is protected route for instructor only"
            })
        }
        next()
    }
    catch(error){ 
        return res.json({
            success: false,
            message: "user role cannot be not verified"
        })
    }
}

// isAdmin
exports.isAdmin = async(req, res, next) => {
    try{
        if(req.user.accountType != "Admin"){
            return res.json({
                success: false,
                message: "this is protected route for admin only"
            })
        }
        next()
    }
    catch(error){ 
        return res.json({
            success: false,
            message: "user role cannot be not verified"
        })
    }
}