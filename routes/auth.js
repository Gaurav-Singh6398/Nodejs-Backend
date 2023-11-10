const express = require('express');
const router = express.Router();
const User = require('../models/User.js');
const { body, validationResult } = require('express-validator');
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
var fetchuser=require('../middleware/fetchuser')

const JWT_SECRET="Gauravisgoodcoder"

router.get('/createUser', [
    body('name').isLength({ min: 3 }),
    body('email').isEmail(),
    body('password').isLength({ min: 5 })
] , async (req, res) => {
 const errors=validationResult(req)
 if(!errors.isEmpty()){
    return res.status(400).json({ errors: errors.array() });
 }
 try{
 let user=await User.findOne({email: req.body.email})
 if(user){
    return res.status(400).json({ errors: "Sorry, email already in use" })
 }
 const salt=await bcrypt.genSalt(10)
 const secPass=await bcrypt.hash(req.body.password,salt)
      
 user=await User.create({
    name:req.body.name,
    email:req.body.email,
    password:secPass
 })
 const data={
    user:user.id
}
 const authtoken=jwt.sign(data,JWT_SECRET)
 res.json({authtoken})
 
}
catch(err){
    console.log(err.message)
    res.status(500).send("Some Error Occured")
}
});



//Authenticate the user 
router.get('/login', [
   body('email','Not a valid EMAIL').isEmail(),
   body('password','Cannot be Empty').exists()
] , async (req, res) => {
    const errors=validationResult(req)
 if(!errors.isEmpty()){
    return res.status(400).json({ errors: errors.array() });
 }
 const{email,password}=req.body
 try{
    let user=await User.findOne({email})
    if(!user){
        return res.status(400).json({error:"Please enter correct credentials"})
    }
    const passwordcompare=await bcrypt.compare(password,user.password)
    if(!passwordcompare){
        return res.status(400).json({error:"Please enter correct credentials"})
    }
    const data={
        user:user.id
    }
    const authtoken=jwt.sign(data,JWT_SECRET)
    res.json({authtoken})
}
catch(err){
    console.log(err.message)
    res.status(500).send("Internal server Error Occured")
}



})
//viewing Details
router.get('/details',fetchuser, async (req, res) => {
try{
   const  userId=req.user
    console.log(userId)
    const user=await User.findById(userId).select("-password")
    console.log(user)
    res.send(user)
    

}
catch(err){
    console.log(err.message)
    res.status(500).send("Internal server Error Occured")
}
})

module.exports = router;


