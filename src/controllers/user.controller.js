import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/coludnary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import  Jwt  from "jsonwebtoken";

const generateAccessAndRefereshToken = async(userId)=>{
try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    // console.log("accessToken:", accessToken);
    // console.log("refereshToken:", refreshToken);

    user.refreshToken = refreshToken;
    await user.save({validateBeforeSave: false});
    console.log("refereshToken:", refreshToken);
    return {accessToken, refreshToken};
    
} catch (error) {
    console.log("error:", error);
    throw new ApiError(500, "something went wrong during generating access and refresh token ")
    
}
}

const registerUser = asyncHandler( async (req,res)=>{
    // Steps 1 get user details from frontend
    // validation - not empty
    // check if user already exists : username and email
    // check for images, check for avatar
    // upload them to cloudnary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response 
    // check for user creation 
    // return res
    

    const {username, fullname, email, password }= req.body
    console.log("email:", email);

    if (
        [fullname, email,username, password].some((field)=>field.trim() ==="")
    ) {
        throw new ApiError(400, "All fields are required");
    }
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    if(existedUser){
        throw new ApiError(409, "User already exists");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImagePath = req.files?.coverImage[0]?.path;
    let coverImagePath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0) {
        coverImagePath = req.files.coverImage[0].path
    } 

    if(!avatarLocalPath){
        throw new ApiError(404, "Avatar file is requrired");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImagePath);
    
    if(!avatar){
        throw new ApiError(400, "Avatar file is requrired");
    }
    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url||"",
        email,
        password,
        username: username.toLowerCase()
    })
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken "
    );

    if(!createdUser){
        throw new ApiError(500, "something went wrong while creating a new user");
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )



})

const loginUser = asyncHandler( async (req,res) => {
    // step 1 get user details from frontend 
    // step 2 send the details to server
    // step 3 if user exist then create a access token and refreshtoken send it to him 
    // step 4 if user does not exist then send error message to user
    // step 5 if user exist then send the user details to user
    // req body -> data
    // username or email
    // find user 
    // password check
    // access and refresh token generation
    // send cookie


    const {email, username, password} = req.body
    if(!username && !email){
        throw new ApiError(400, "Username or email is required");
    }
    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    if(!user){
        throw new ApiError(404, "User not found");
    }
    const isPasswordValid = await user.isPasswordCorrect(password);
    if(!isPasswordValid){
        throw new ApiError(401, "Invalid password");
    }
    const {accessToken, refreshToken} = await generateAccessAndRefereshToken(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refereshToken");

    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken,
                accessToken
            },
            "User logged in Successfully"
        )
    )


    
})

const logoutUser = asyncHandler(async(req,res) => {
    User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                 refereshToken: 1 // this removes the field from document
            }
        },
        {
            new : true
        } 
    )
    const options = {
        httpOnly: true,
        secure: true
    }
    return res.status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "user logged Out"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorized request");
    }
    try {
        const decodedToken = Jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    
        const user = await User.findById(decodedToken?._id);
        if(!user){
            throw new ApiError(401, "Invalid refresh token");
        }
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh token is expired or used");
        
        }
        const option = {
            httpOnly: true,
            secure: true
        
        }
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshToken(user._id);
    
        return res
        .status(200)
        .cookie("access_token", accessToken, option)
        .cookie("refresh_token", newRefreshToken, option)
        .json(
            new ApiResponse(
                200,
                {accessToken, newRefreshToken},
                "Access token refreshed successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token");
        
    }


})

const changeCurrentPassword = asyncHandler(async(req,res) => {
    const {oldPassword, newPassword} = req.body
     
    const user = await User.findById(req.user?._id);

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect) {
        throw new ApiError(401, "Invalid old password");
    }
    user.password = newPassword;
    await user.save({validateBeforeSave: false})
    return res
    .status(200)
    .json(new ApiResponse(200, {}, "password changed successfully"))
})

const getCurrentUser = asyncHandler(async (req,res) => {
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "current user fetched successfully"))
})

const updateAccountDetails = asyncHandler(async (req,res) => {
    const {fullname, email} = req.body;
    if(!fullname || !email){
        throw new ApiError(400, "fullname and email are required");
    }
    
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullname,
                email,
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,user, "Account details updated successfully"))
})

const updateUserAvatar = asyncHandler(async(req,res)=>{
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is missing");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    if(!avatar.url){
        throw new ApiError(400, "Error while uploading on avatar");
    }
    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"avatar updated successfully")
    )
})

const updateUserCoverImage = asyncHandler(async(req,res)=>{
    const coverLocalPath = req.file?.path

    if(!coverLocalPath){
        throw new ApiError(400, "CoverImage file is missing");
    }
    const coverImage = await uploadOnCloudinary(coverLocalPath);
    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading cover image");
    }
    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"cover image updated successfully")
    )
})


const getUserChannelProfile = asyncHandler(async(req,res)=>{
    const {username} = req.params;
    
    if(!username?.trim()){
        throw new ApiError(400, "Username is required");
    }

    const channel = await User.aggregate([
        {
            $match: {
                username: username
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localFiled: "_id",
                foregnField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localFiled: "_id",
                foregnField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "subscribers"
                },
                channelsSubscribedToCount:{
                    $size: "subscribedTo"
                },
                isScribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullname:1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                avatar: 1,
                coverImage: 1,
                email: 1,

            }
        }
    
        
    
    ])

    if(!channel?.length){
        throw new ApiError(404, "Channel does not exists");
    }
    return res
    .status(200)
    .json(
        new ApiResponse(200, channel[0], "user channel fetched successfully")
    )
})

const getWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate([
        {
            $math: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localFiled: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullname: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },{
                        $addFields: {
                            owner: {
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0]?.watchHistory,
            "watch history fetched successfully"
        )
    )
})


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}