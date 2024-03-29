import {v2 as cloudinary} from "cloudinary"
import fs from "fs"

cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET
  });

  const uploadOnCloudinary = async(localFIlePath)=>{
    try {
        if(!localFIlePath)return null

        // upload the file on cloudnary
        const response= await cloudinary.uploader.upload(localFIlePath, {
            resource_type: "auto"
        })
        // file has been uploaded successfully
        // console.log("file is uploaded on cloudinary", response.url);
        fs.unlinkSync(localFIlePath)  //remove the locally saved temp file as the operation got failed
        return response;
        
    } catch (error) {
        fs.unlinkSync(localFIlePath)  //remove the locally saved temp file as the operation got failed
        return null;
    }
  }

export {uploadOnCloudinary}
//   cloudinary.uploader.upload("https://upload.wikimedia.org/wikipedia/commons/a/ae/Olympic_flag.jpg",
//   { public_id: "olympic_flag" }, 
//   function(error, result) {console.log(result); });
