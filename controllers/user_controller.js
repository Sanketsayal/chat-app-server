const User=require('../models/user.js')
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
require('dotenv').config()

module.exports.register=async (req,res)=>{
    try {
        const {username,password,avatarImage,email}=req.body
        let user=await User.findOne({email:req.body.email})
        const hashPassword=await bcrypt.hash(password,10)
        if(!user){
            user=await User.create({
                username,
                email,
                avatar:avatarImage,
                password:hashPassword
            });
        }
        delete user._doc.password
        const accessToken=jwt.sign(
            {email},
            process.env.ACCESS_TOKEN_SECRET,
            {expiresIn:'1h'}
        )

        const refreshToken=jwt.sign(
            {email},
            process.env.REFRESH_TOKEN_SECRET,
            {expiresIn:'3d'}
        )

        res.cookie('jwt',refreshToken,{
            httpOnly: true,
            secure: true,
            signed: true,
            sameSite: 'None',
            maxAge: 3 * 24 * 60 * 60 * 1000
        })

        return res.json(200,{
            message:'signing up successful!!',
            data:{
                user,
                token:accessToken,
            }
        })
        //return res.status(200).json({message:'Registration Successful'})
    } catch (error) {
        console.log(error)
        return res.status(500).json({message:'Interal server error'})
        
    }
}

module.exports.signin=async (req,res)=>{
    try {
        const {email,password}=req.body
        let user=await User.findOne({email:email})
        if(!user){
            return res.status(401).json({message:'User not found'})
        }
        let passwordCorrect=bcrypt.compareSync(password,user.password)
        if(!passwordCorrect){
            return res.status(401).json({message:'Email and Password Incorrect'})
        }
        delete user._doc.password

        const accessToken=jwt.sign(
            {email},
            process.env.ACCESS_TOKEN_SECRET,
            {expiresIn:'1h'}
        )

        const refreshToken=jwt.sign(
            {email},
            process.env.REFRESH_TOKEN_SECRET,
            {expiresIn:'3d'}
        )

        res.cookie('jwt',refreshToken,{
            httpOnly: true,
            secure: true,
            signed: true,
            sameSite: 'None',
            maxAge: 3 * 24 * 60 * 60 * 1000
        })

        return res.json(200,{
            message:'signing in successful!!',
            data:{
                user,
                token:accessToken,
            }
        })
    } catch (error) {
        console.log(error);
    }
}

module.exports.refresh=async (req,res)=>{
    const cookies=req.signedCookies
    if(!cookies?.jwt){
        return res.status(401).json({message:'Unauthorized'})
    }
    const refreshToken=cookies.jwt

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err,decoded)=>{
            if(err){
                return res.status(403).json({message:'Forbidden'})
            }
            const email=decoded.email
            const user=await User.findOne({email:email})
            if (!user) {
                return res.status(401).json({ message: 'Unauthorized' })
            }

            const accessToken=jwt.sign(
                {email},
                process.env.ACCESS_TOKEN_SECRET,
                {expiresIn:'1h'}
            )

            return res.json({token:accessToken})
        }
    )
}

module.exports.logout=async (req,res)=>{
    const cookies=req.signedCookies
    if(!cookies?.jwt){
        return res.status(401).json({message:'Unauthorized'})
    }

    res.clearCookie('jwt', {
        httpOnly: true,
        secure: true,
        signed: true,
        sameSite: 'None',
    })

    return res.json({message:'Logout Success!!'})
}