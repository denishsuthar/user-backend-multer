import { User } from "../model/userModel.js";
import catchAsyncError from "../middelware/catchAsyncError.js"
import ErrorHandler from "../utils/errorHandler.js"
import sendToken from "../utils/sendToken.js"
import sendEmail from "../utils/sendEmail.js";
import crypto from "crypto"

// Register User
export const register = catchAsyncError(async(req, res, next)=>{
    const {name, email, password, mobileNumber} = req.body
    const avatar = req.file
    if(!name || !email || !password || !mobileNumber || !avatar) return next(new ErrorHandler("Please Enter All Fields", 400));

    let user = await User.findOne({email})
    if(user) return next(new ErrorHandler("User Already Registered, Please Login", 400));

    user = await User.create({
        name, email, password, mobileNumber, avatar
    })

    sendToken(res, user, "Registred Successfully", 201)
})

// export const registerManyImages = catchAsyncError(async(req, res, next)=>{
//     const {name, email, password, mobileNumber} = req.body
//     const images = req.files
//     if(!name || !email || !password || !mobileNumber || !images) return next(new ErrorHandler("Please Enter All Fields", 400));

//     let user = await User.findOne({email})
//     if(user) return next(new ErrorHandler("User Already Registered, Please Login", 400));

//     user = await User.create({
//         name, email, password, mobileNumber, images
//     })

//     sendToken(res, user, "Registred Successfully", 201)
// })

// Login User
export const login = catchAsyncError(async(req, res, next)=>{
    const {email, password} = req.body
    if(!email || !password) return next(new ErrorHandler("Please Enter All Fields", 400))

    const user = await User.findOne({email}).select("+password")
    if(!user) return next(new ErrorHandler("Incorrect Email", 401))

    const isMatch = await user.comparePassword(password);
    if(!isMatch) return next(new ErrorHandler("Incorrect Password", 401));

    sendToken(res, user, `Welcome Back ${user.name}`, 200);

})

// Logout User
export const logout = catchAsyncError(async(req, res, next)=>{
    res.status(200).cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly:true,
        // secure:true,
        // sameSite:"none"
    }).json({
        success:true,
        message:"Logout SuccessFully"
    })
})

// Forgot Password
export const forgotPassword = catchAsyncError(async(req, res,next)=>{
    const user = await User.findOne({email:req.body.email})
    if(!user) return next(new ErrorHandler("User Not Found", 404));

    // Get ResetPassword Token
    const resetToken = user.getResetPasswordToken();

    await user.save({ validateBeforeSave: false });

    const resetPasswordUrl = `${req.protocol}://${req.get("host")}/api/v1/password/reset/${resetToken}`;

    const message = `Your password reset token is :- \n\n ${resetPasswordUrl} \n\nIf you have not requested this email then, please ignore it.`;

    try {
        await sendEmail({
          email: user.email,
          subject: `Password Recovery`,
          message,
        });
    
        res.status(200).json({
          success: true,
          message: `Email sent to ${user.email} successfully`,
        });
      } catch (error) {
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
    
        await user.save({ validateBeforeSave: false });
    
        return next(new ErrorHandler(error.message, 500));
      }
})

// Reset Password
export const resetPassword = catchAsyncError(async(req, res, next)=>{
    // Creating Token Hash
    const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {return next(new ErrorHandler("Reset Password Token is invalid or has been expired",400));
  }

  if (req.body.password !== req.body.confirmPassword) {
    return next(new ErrorHandler("Password is not match", 400));
  }
  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;

  await user.save();

  sendToken(res, user, "Password Reset Succesfully", 200)
})

// Get Login User Profile
export const myProfile = catchAsyncError(async(req,res,next)=>{
    const user = await User.findById(req.user.id)
    res.status(200).json({
        success:true,
        user
    })
})

// Update User Profile
export const updateProfile = catchAsyncError(async(req,res,next)=>{
    const {name, email, mobileNumber} = req.body

    const user = await User.findById(req.user.id);
    if(name) user.name = name;
    if(email) user.email = email;
    if(mobileNumber) user.mobileNumber = mobileNumber;

    await user.save();

    res.status(200).json({
        success:true,
        message:"Profile Updated Successfully",
        user
    })
})

// Update User Password
export const updatePassword = catchAsyncError(async(req, res, next)=>{
    const {oldPassword, newPassword} = req.body
    if(!oldPassword || !newPassword) return next(new ErrorHandler("Please Fill All Fields", 400));

    const user = await User.findById(req.user._id).select("+password");

    const isMatch = await user.comparePassword(oldPassword);
    if(!isMatch) return next(new ErrorHandler("Old Password Incorrect", 400));

    user.password = newPassword;
    
    await user.save();

    res.status(200).json({
        success:true,
        message:"Password Changed Successfully"
    })
})

// Get All Users --Admin
export const allUsers = catchAsyncError(async(req,res,next)=>{
    const users = await User.find();
    res.status(200).json({
        success:true,
        users
    })
})

// Get Any User Profile --Admin
export const findUser = catchAsyncError(async(req, res, next)=>{
    const user = await User.findById(req.params.id)
    if(!user) return next(new ErrorHandler("User Not Found", 404));
    res.status(200).json({
        success:true,
        user
    })
})

// Update User Role --Admin
export const updateRole = catchAsyncError(async(req, res, next)=>{
    const user = await User.findById(req.params.id);
    if(!user) return next(new ErrorHandler("User Not Found", 404));

    if(user.role === "user") user.role = "admin";
    else user.role = "user";

    await user.save();

    res.status(200).json({
        success:true,
        message:"Role Updated"
    })
})

// Delete User --Admin
export const deleteUser = catchAsyncError(async(req, res, next)=>{
    const user = await User.findById(req.params.id)
    if(!user) return next(new ErrorHandler("User Not Found", 404));

    await user.deleteOne();

    res.status(200).json({
        success:true,
        message:"User Deleted Successfully"
    })
})