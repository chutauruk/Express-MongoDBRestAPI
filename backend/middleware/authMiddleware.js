const jwt = require('jsonwebtoken')   //function running during request/response cycle to run and check the token
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

const protect = asyncHandler(async (req, res, next) => {
    let token
    
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){ //token sent to authorization header in format labeled as bearer token
        try{
            // Get token from header
            token = req.headers.authorization.split(' ')[1] //getting token from bearer auth turned into array (bearer at 0, token at 1 index)
        
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        // Get user from the token
        req.user = await User.findById(decoded.id).select('-password')    // token has userid as a payload, assign it to access any protected route
        
        next()
    } catch (error) {
        console.log(error)
        res.status(401)
        throw new Error('Not authorized')
        }
    }

if(!token) {
    res.status(401)
    throw new Error('Not authorized, no token')
}
})

module.exports = { protect }