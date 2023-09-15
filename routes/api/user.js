const express=require('express')
const router=express.Router()
const userController=require('../../controllers/user_controller')

router.post('/register',userController.register)
router.post('/sign-in',userController.signin)
router.get('/refresh',userController.refresh)
router.get('/logout',userController.logout)

module.exports=router