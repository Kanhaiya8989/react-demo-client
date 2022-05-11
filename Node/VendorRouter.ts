import { Router } from "express";
const router = Router();
import { VendorCreate, verifyUserMail, OtpVerification, VendorLoginByEmail, VendorLoginByPhone, GetVendorProfile, UpdateVendorProfile, ForgetPassword, ResetForgetPassword, ChangePassword, UpdatePhone, VerifyUpdatedPhoneOTP, UpdateEmail, VerifyOTPUpdateEmail, ResendOTP, s3ImageUpload } from '../../controllers/vendor/VendorController';
import { checkAuthVendor } from "../../middleware/auth";

const multer = require('multer')
import multerS3  from 'multer-s3'
import AWS from 'aws-sdk';



const storage = multer.diskStorage({
    destination: function (req: Request, file: Express.Multer.File, cb: any) {
        cb(null, './src/vendorImage')
    },
    filename: function (req: Request, file: Express.Multer.File, cb: any) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, uniqueSuffix + '-' + file.originalname)
    }
})
const upload = multer({  storage: storage  }).single('profile_image')


AWS.config.update({
    secretAccessKey: process.env.AWS_ACCESS_SECRET_KEY,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    region: process.env.AWS_REGION
});

var s3 = new AWS.S3();

const uploadS3 = multer({
    storage: multerS3({
      s3: s3,
      bucket: process.env.AWS_BUCKET || "famatestorage",
      metadata: function (req, file, cb) {
        cb(null, {fieldName: file.fieldname});
      },
      key: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, uniqueSuffix + '-' + file.originalname)
      }
    })
  }).single('image')


router.route('/vendor-singup').post(upload, VendorCreate);
router.route('/email-verification').get(verifyUserMail);
router.route('/otp-verification').post(OtpVerification);
router.route('/login-by-email').post(VendorLoginByEmail);
router.route('/login-by-phone').post(VendorLoginByPhone);
router.route('/vendor-forget-password').post(ForgetPassword);
router.route('/vendor-reset-forget-password').post(ResetForgetPassword);
router.route('/get-vendor-profile').get(checkAuthVendor, GetVendorProfile);
router.route('/update-vendor-profile').put(checkAuthVendor, UpdateVendorProfile);
router.route('/change-password').put(checkAuthVendor, ChangePassword);
router.route('/update-phone').put(checkAuthVendor, UpdatePhone);
router.route('/update-email').put(checkAuthVendor, UpdateEmail);
router.route('/verify-updated-phone').put(checkAuthVendor, VerifyUpdatedPhoneOTP);
router.route('/verify-updated-email').put(checkAuthVendor, VerifyOTPUpdateEmail);
router.route('/resend-otp-email-phone').post(checkAuthVendor, ResendOTP);

router.route('/s3-image-upload').post(uploadS3, s3ImageUpload);


export default router; 