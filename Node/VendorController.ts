import { RequestHandler } from "express";
import Vendor, { VendorI } from '../../models/VendorModel';
import createHttpError, { InternalServerError } from "http-errors";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Twilio } from "twilio";
import { JWT_KEY, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, transporter, BASE_URL, FRONT_END_VENDOR_BASE_URL } from '../../config/config';
import { generateOtp } from '../../utils/helper';

const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
interface CurrentUserI{
    Id:string
    email: string
}


//vendor create method helps us to create a vendor
export const VendorCreate: RequestHandler = async (req, res, next) => {

    const { email, password, first_name, last_name, phone_number, country_code } = req.body;
    const profile_image = req.file?.filename;

    try {

        const existingVendor = await Vendor.findOne({ where: { email, phone_number } });

        if (existingVendor) {
            return next(createHttpError(406, `Vendor is already registered with this email and phone number`))
        }

        const existingEmail = await Vendor.findOne({ where: { email } })

        if (existingEmail) {
            return next(createHttpError(406, `Vendor is already registered with this email`))
        }

        const existingPhone = await Vendor.findOne({ where: { phone_number } })

        if (existingPhone) {
            return next(createHttpError(406, `Vendor is already registered with this phone number`))
        }

        const hashPassword = await bcrypt.hash(password, 8);

        const vendor = new Vendor({ email, password: hashPassword, first_name, last_name, profile_image, phone_number, country_code });
        await vendor.save().then(async (result) => {
            if (result) {

                const encryptedToken = jwt.sign({ email: email, Id: result.Id }, JWT_KEY, {})
                const jwttoken = jwt.sign({ email: email.toString() }, JWT_KEY, {});

                let mailOptions = {
                    from: 'akshitgupta0007@gmail.com',
                    to: `${email}`,
                    subject: "Verification email from Famate",
                    html: `<a href="${BASE_URL}/api/vendor/web/email-verification?verify_token=${jwttoken}">Verify Email</a>`
                }

                await transporter.sendMail(mailOptions, async (error, info) => {
                    if (error) {
                        return next(createHttpError(401, error.message))
                    } else {
                        await Vendor.update({ remember_token: encryptedToken }, { where: { Id: result.Id } }).then(async (update_result) => {
                            if (update_result) {
                                let user_otp = generateOtp();

                                await Vendor.update({ otp: user_otp }, { where: { Id: result.Id } }).then(async (otp_result) => {
                                    if (otp_result) {
                                        // const client = new Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
                                        // client.messages.create({
                                        //         body: `Your Famate phone number verification code is:${user_otp}`,
                                        //         from: '+12082138609',
                                        //         to: `${phone_number}`
                                        // }).then((message) => {
                                        //         res.json({
                                        //                 status: 'true',
                                        //                 message: `You have sucessfully register with Famte`,
                                        //                 data: { user, user_token: encryptedToken }
                                        //         })
                                        // }).catch((error) => {
                                        //         return next(createHttpError(401, error.message))
                                        // })
                                        const data = await Vendor.findOne({ where: { email } })
                                        res.json({
                                            status: true,
                                            message: 'You have sucessfully register with Famte as vendor',
                                            data,
                                            token: encryptedToken
                                        })
                                    }

                                }).catch((error) => { return next(createHttpError(401, error.message)) })
                            }
                        }).catch((error) => { return next(createHttpError(401, error.message)) });
                    }
                });
            }
        }).catch((error) => {
            return next(createHttpError(406, error.message))
        });

    } catch (error: any) {
        return next(createHttpError(401, error.message))
    }
}

//verifying the user email
export const verifyUserMail: RequestHandler = async (req, res, next) => {

    const verify_token: string = req.query.verify_token as string;

    try {

        const decodetoken = jwt.verify(verify_token, JWT_KEY) as VendorI;

        const vendor = await Vendor.findOne({ where: { email: decodetoken.email } })

        if (!vendor) {
            return next(createHttpError(404, "vendor doesn't exist"))
        }

        if (vendor.email_verify) {
            return next(createHttpError(404, "vendor already verified"))
        }

        await Vendor.update({ email_verify: 1 }, { where: { Id: vendor.Id } }).then(async (result) => {
            if (result) {
                res.json({
                    status: true,
                    message: `Your email has been verified sucessfully`
                })
            }
        }).catch((error) => { return next(createHttpError(401, error.message)) });

    } catch (error: any) {
        return next(createHttpError(401, error.message))
    }
}

//handling OTP Verification
export const OtpVerification: RequestHandler = async (req, res, next) => {

    const { phone_number, country_code, otp } = req.body;

    try {
        const vendor = await Vendor.findOne({ where: { phone_number } });
        if (!vendor) {
            return next(createHttpError(404, `Vendor doesn't exist`))
        }

        if (vendor.otp !== otp) {
            return next(createHttpError(404, `OTP doesn't match`))
        }

        const encryptedToken = jwt.sign({ Id: vendor.Id }, JWT_KEY, {})

        await Vendor.update({ otp: null, remember_token: encryptedToken, phone_verify: 1 }, { where: { Id: vendor.Id } }).then(async (result) => {
            if (result) {
                const data = await Vendor.findOne({ where: { phone_number } })
                res.json({
                    status: true,
                    message: "Login Success",
                    data,
                    token: encryptedToken
                })
            }

        }).catch((error) => { return next(createHttpError(401, error.message)) })

    } catch (error: any) {
        return next(createHttpError(401, error.message))
    }
}

//Vendor Login Using Email and Password
export const VendorLoginByEmail: RequestHandler = async (req, res, next) => {
    const { email, password } = req.body;

    try {
        const vendor = await Vendor.findOne({ where: { email } })

        if (!vendor) {
            return next(createHttpError(404, `vendor doesn't exist`))
        }

        if (!vendor.email_verify) {

            const jwttoken = jwt.sign({ email: vendor.email }, JWT_KEY, { expiresIn: "60m" });

            let mailOptions = {
                from: 'akshitgupta0007@gmail.com',
                to: `${email}`,
                subject: "Verification email from Famate",
                html: `<a href="${BASE_URL}/api/vendor/web/email-verification?verify_token=${jwttoken}">Verify Email</a>`
            }

            await transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    return next(createHttpError(401, error.message))
                }
            });
            return next(createHttpError(401, 'Kindly verify your email. A verification link has been sent to your registered email'))
        }

        const isValidPassword = await bcrypt.compare(password, vendor.password);

        if (!isValidPassword) {
            return next(createHttpError(401, `invalid login credential`));
        }

        const encryptedToken = jwt.sign({Id: vendor.Id }, JWT_KEY, {});

        await Vendor.update({ remember_token: encryptedToken }, { where: { Id: vendor.Id } }).then(async (result) => {
            if (result) {
                const data = await Vendor.findOne({ where: { email } })
                res.json({
                    status: true,
                    message: 'login Successfull',
                    data,
                    token: encryptedToken
                });
            }
        }).catch((error: any) => {
            return next(createHttpError(401, error.message))
        })

    } catch (error: any) {
        return next(createHttpError(401, error.message))
    }
}

//Vendor Login Using Phone Number and OTP
export const VendorLoginByPhone: RequestHandler = async (req, res, next) => {
    const { phone_number, country_code } = req.body;

    try {
        const vendor = await Vendor.findOne({ where: { phone_number } });

        if (!vendor) {
            return next(createHttpError(404, `vendor doesn't exist`))
        }

        let user_otp = generateOtp();

        await Vendor.update({ otp: user_otp }, { where: { Id: vendor.Id } }).then(async (result) => {

            if (result) {
                const data = await Vendor.findOne({ where: { phone_number } });
                res.json({
                    status: true,
                    message: 'Otp has been sent to the mobile number',
                    data
                })
            }
            // const client = new Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
            // client.messages.create({
            //         body: `Your Famate phone number verification code is:${user_otp}`,
            //         from: '+12082138609',
            //         to: `${phone_number}`
            // }).then((message) => {
            //         res.json({
            //                 status: 'true',
            //                 message: `Otp has been sent to the mobile number ${phone_number}`
            //         })
            // }).catch((error) => {
            //         return next(createHttpError(401, error.message))
            // })

        }).catch((error) => { return next(createHttpError(401, error.message)) })
    } catch (error: any) {
        return next(createHttpError(401, error.message))
    }
}

//Get Vendor Profile handling
export const GetVendorProfile: RequestHandler = async (req, res, next) =>{
   
    const { Id } = req.user as CurrentUserI;

    try {

        const data = await Vendor.findOne({where:{Id}})

        if(!data)
        {
            return next(createHttpError(404, "Vendor doesn't exist"))
        }

        res.json({
            status:true,
            message:'Profile Data',
            data
        })
        
    } catch (error: any) {
        return next(createHttpError(406, error.message))
    }
}

//Update Vendor Profile
export const UpdateVendorProfile: RequestHandler = async (req, res, next) => {

    const { first_name, last_name, email, phone_number } = req.body;
    const { Id } = req.user as CurrentUserI;

    try {

        const vendor = await Vendor.findOne({ where: { Id } })

        if (!vendor) {
            return next(createHttpError(404, "Vendor doesn't exist"))
        }

        const encryptedToken = jwt.sign({email: email, Id: Id}, JWT_KEY, {});

        await Vendor.update({ first_name, last_name, email, phone_number, remember_token: encryptedToken }, { where: { Id } }).then(async (result) => {
            if (result) {
                const data = await Vendor.findOne({ where: { Id } })
                res.json({
                    status: true,
                    message: 'Profile Update Successful',
                    data,
                    token:encryptedToken
                })
            }
        }).catch((error) => {
            return next(createHttpError(406, error.message));
        })
    } catch (error: any) {
        return next(createHttpError(406, error.message))
    }
}

//Handling Vendor Forget Password
export const ForgetPassword: RequestHandler = async (req, res, next) => {

    const { email } = req.body;

    try {

        const vendor = await Vendor.findOne({ where: { email } });

        if (!vendor) {
            return next(createHttpError(404, "You are not a vendor"));
        }

        const jwttoken = jwt.sign({email:email}, JWT_KEY, {});

        let mailOptions = {
            from: 'akshitgupta0007@gmail.com',
            to: `${email}`,
            subject: "Forget Password email from Famate",
            html: `<a href="${FRONT_END_VENDOR_BASE_URL}/reset-password?verify_token=${jwttoken}">RESET FORGET PASSWORD</a>`
        }

        await transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return next(createHttpError(401, error.message))
            }
        });

        const data = await Vendor.findOne({ where: { email } });
        res.json({
            status: true,
            message: 'A mail has been sent to your email',
            data
        })
    } catch (error: any) {
        return next(createHttpError(401, error.message));
    }
}

//Handling Vendor Reset Forget Password
export const ResetForgetPassword: RequestHandler = async (req, res, next) => {

    const { new_password, token } = req.body;

    try {

        if (!token) {
            return next(createHttpError(406, 'Unauthorization Error'));
        }

        jwt.verify(token.verify_token, JWT_KEY, async (err: any, user: any) => {
            if (err) {
                return next(createHttpError(406, 'Invalid User'))
            }


            const encryptPassword = await bcrypt.hash(new_password, 8);

            await Vendor.update({ password: encryptPassword }, { where: { email: user.email } }).then(async (result) => {
                if (result) {
                    const data = await Vendor.findOne({ where: { email: user.email } });
                    res.json({
                        status: true,
                        message: 'Password has been reset successfully',
                        data
                    })
                }
            }).catch((error) => {
                return next(createHttpError(401, error.message));
            })
        })

    } catch (error: any) {
        return next(createHttpError(401, error.message));
    }
}

//Vendor Change Password
export const ChangePassword: RequestHandler = async (req, res, next) =>{
    const { old_password, new_password } = req.body;
    const { Id } = req.user as CurrentUserI;

    try {
        
        const existUser = await Vendor.findOne({where:{Id}})

        if(!existUser){
            return next(createHttpError(406, "Vendor doesn't exist"))
        }

        const isValidPassword = await bcrypt.compare(old_password, existUser.password);

        if (!isValidPassword) {
                return next(createHttpError(406, `Current password doesn't match`));
        }

        const encodePassowrd = await bcrypt.hash(new_password, 8);

        await Vendor.update({ password: encodePassowrd }, { where: { Id } }).then(async (result) => {
                if (result) {
                        const data = await Vendor.findOne({ where: { Id } });
                        res.json({
                                status: true,
                                message: 'Password changed successfully',
                                data
                        })
                }
        }).catch((error) => {
                return next(createHttpError(401, error.message))
        })
    } catch (error: any) {
        return next(createHttpError(406, error.message))
    }
}

//Update Vendor Phone Number
export const UpdatePhone: RequestHandler = async (req, res, next) => {
    const { phone_number } = req.body;
    const { Id } = req.user as CurrentUserI;

    try {
            const user = await Vendor.findOne({ where: { Id } });

            if (!user) {
                    return next(createHttpError(404, "Vendor doesn't exist"));
            }

            const isSameExist = await Vendor.findOne({ where: { phone_number, Id } });

            if (isSameExist) {
                    return next(createHttpError(200, 'You have registered with same phone number'))
            }

            const isPhoneExist = await Vendor.findOne({ where: { phone_number } });

            if (isPhoneExist) {
                    return next(createHttpError(200, 'Phone Number already exist'))
            }

            let user_otp = generateOtp();

            await Vendor.update({ otp: user_otp, phone_verify:0 }, { where: { Id } }).then(async (result) => {
                    if (result) {

                            // const client = new Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
                            // client.messages.create({
                            //         body: `Your Famate phone number verification code is:${user_otp}`,
                            //         from: '+12082138609',
                            //         to: `${phone_number}`
                            // }).then((message) => {
                            //         res.json({
                            //                 status: 'true',
                            //                 message: `Otp has been sent to the mobile number ${phone_number}`
                            //         })
                            // }).catch((error) => {
                            //         return next(createHttpError(401, error.message))
                            // })
                            const data = await Vendor.findOne({ where: { Id } });
                            res.json({
                                    status: true,
                                    message: 'OTP has been sent',
                                    data
                            })
                    }
            }).catch((error) => {
                    return next(createHttpError(401, error.message));
            })
    } catch (error: any) {
            return next(createHttpError(401, error.message))
    }
}

//Verify Updated Vendor Phone Number
export const VerifyUpdatedPhoneOTP: RequestHandler = async (req, res, next) =>{

    const { phone_number, otp, country_code} = req.body;
    const { Id } = req.user as CurrentUserI;

    try {

            const user = await Vendor.findOne({where:{Id}});

            if(!user)
            {
                    return next(createHttpError(404, "Vendor doesn't exist"))
            }

            if(user.otp !== otp)
            {
                    return next(createHttpError(401, "OTP doesn't match"));
            }

            await Vendor.update({phone_number:phone_number, country_code:country_code, phone_verify: 1, otp:null}, {where:{Id}}).then(async (result) =>{
                    if(result)
                    {
                       const data = await Vendor.findOne({where:{Id}});
                       res.json({
                               status:true,
                               message:'Phone number updated successfully',
                               data
                       })
                    }
            }).catch((error) =>{
                    return next(createHttpError(401, error.message));
            })
            
    } catch (error: any) {
            return next(createHttpError(401, error.message));
    }
}

//Update Vendor Email Address
export const UpdateEmail: RequestHandler = async (req, res, next) => {
    const { email } = req.body;
    const { Id } = req.user as CurrentUserI;

    try {
            const user = await Vendor.findOne({ where: { Id } });

            if (!user) {
                    return next(createHttpError(404, "Vendor doesn't exist"));
            }

            const isSameExist = await Vendor.findOne({ where: { email, Id } });

            if (isSameExist) {
                    return next(createHttpError(200, 'You have registered with same email address'))
            }

            const isEmailExist = await Vendor.findOne({ where: { email } });

            if (isEmailExist) {
                    return next(createHttpError(200, 'Email already exist'))
            }

            let user_otp = generateOtp();

            await Vendor.update({ email_verify: 0, email: email, otp: user_otp }, { where: { Id } }).then(async (result) => {
                    if (result) {
                            let mailOptions = {
                                    from: 'akshitgupta0007@gmail.com',
                                    to: `${email}`,
                                    subject: "Email Verification",
                                    text: `Your email update OTP is: ${user_otp}`
                            }

                            await transporter.sendMail(mailOptions, async (error, info) => {
                                    if (error) {
                                            return next(createHttpError(406, error.message))
                                    } else {
                                            const data = await Vendor.findOne({ where: { Id } });
                                            res.json({
                                                    status: true,
                                                    message: `A OTP has been sent to your email. Kindly verify your updated email.`,
                                                    data
                                            })
                                    }
                            });
                    }
            }).catch((error) => {
                    return next(createHttpError(406, error.message));
            })
    } catch (error: any) {
            return next(createHttpError(406, error.message))
    }
}

//Verify Email Update OTP
export const VerifyOTPUpdateEmail: RequestHandler = async (req, res, next) => {
    const { otp } = req.body;
    const { Id } = req.user as CurrentUserI;

    try {
        const user = await Vendor.findOne({ where: { Id } });

        if (!user) {
            return next(createHttpError(404, "Vendor doesn't exist"));
        }

        if(otp != user.otp){
            return next(createHttpError(406, "OTP doesn't match"));
        }

        await Vendor.update({ email_verify: 1, otp: null }, { where: { Id } }).then(async (result) => {
            if (result) {
                const data = await Vendor.findOne({ where: { Id } });
                res.json({
                    status: true,
                    message: `Email Verify Successfully`,
                    data
                })
            }
        }).catch((error) => {
            return next(createHttpError(406, error.message));
        })
    } catch (error: any) {
        return next(createHttpError(406, error.message))
    }
}

//Resend OTP Handle
export const ResendOTP: RequestHandler = async (req, res, next) => {

    const { type } = req.body;
    const { Id } = req.user as CurrentUserI;

    try {
        const user = await Vendor.findOne({ where: { Id } });

        if (!user) {
            return next(createHttpError(404, `Vendor doesn't exist`))
        }

        if (!type) {
            return next(createHttpError(406, `Type is required`))
        }

        let user_otp = generateOtp();

        if (type === 'phone') {
            await Vendor.update({ otp: user_otp }, { where: { Id } }).then(async (result) => {
                if (result) {
                    const data = await Vendor.findOne({ where: { Id } });
                    res.json({
                        status: true,
                        message: `OTP has been sent to your registered ${type}`,
                        data
                    })
                }
            }).catch((error) => { return next(createHttpError(406, error.message)) })

            // const client = new Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
            // client.messages.create({
            //         body: `Your Famate phone number verification code is:${user_otp}`,
            //         from: '+12082138609',
            //         to: `${phone_number}`
            // }).then((message) => {
            //         res.json({
            //                 status: 'true',
            //                 message: `Otp has been sent to the mobile number ${phone_number}`
            //         })
            // }).catch((error) => {
            //         return next(createHttpError(401, error.message))
            // })

        }

        if (type === 'email') {
            await Vendor.update({ otp: user_otp }, { where: { Id } }).then(async (result) => {
                if (result) {
                    let mailOptions = {
                        from: 'akshitgupta0007@gmail.com',
                        to: `${user.email}`,
                        subject: "Resend OTP from Famate",
                        text: `Your Famate OTP for email verification: ${user_otp}`
                    }
                    await transporter.sendMail(mailOptions, async (error, info) => {
                        if (error) {
                            return next(createHttpError(401, error.message))
                        } else {
                            const data = await Vendor.findOne({ where: { Id } });
                            res.json({
                                status: true,
                                message: `OTP has been sent to your registered ${type}`,
                                data
                            })
                        }
                    });

                }
            }).catch((error) => { return next(createHttpError(401, error.message)) });
        }
    } catch (error: any) {
        return next(createHttpError(406, error.message))
    }
}

//S3 bucket upload
export const s3ImageUpload: RequestHandler = (req, res, next) => {
    const pro = uniqueSuffix + '-' + req.file?.originalname;
    res.json({
        status:true,
        message:'Upload Successfull',
        data: pro
    })
}












