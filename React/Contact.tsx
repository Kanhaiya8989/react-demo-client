import React, { Fragment, useState, useEffect } from 'react';
import { SendConatctUsAction } from '../../actions/HelpAction';
import { validateFields } from '../../utils/Validation';
import { useDispatch, useSelector } from 'react-redux';
import { toast } from 'react-toastify';
import { clearError, ClearMessage } from '../../actions/VendorAction';
import Loader from '../../components/layout/Loader';
import classnames from 'classnames';

const Contact = () => {

    const dispatch = useDispatch()

    const [contactDetail, setContactDetail] = useState({
        name:'',
        email:'',
        phone:'',
        message:''
    })

    const [validation, setValidation] = useState({
        nameError: '',
        emailError: '',
        messageError: '',
        phoneError: ''
    })

    const {error, loading, contactus} = useSelector((state: any) => state.SendContactUs);

    useEffect(() =>{

        if(error){
            toast.error(error)
            dispatch(clearError())
        }

        if(contactus){
            toast.success(contactus)
            dispatch(ClearMessage())
        }

    }, [contactus, error, dispatch])

    const handleContact = (event: any) =>{
        setContactDetail({
            ...contactDetail, [event.target.name]: event.target.value
        })
    }

    const handleSubmit = (event: any) =>{
        event.preventDefault();
        const nameError = validateFields.validateFirstName(contactDetail.name);
        const emailError = validateFields.validateEmail(contactDetail.email);
        const messageError = validateFields.validateMessage(contactDetail.message);
        const phoneError = validateFields.validatePhoneNumber(contactDetail.phone);

        if ([nameError, emailError, messageError, phoneError].every(e => e === false)) {
            setValidation({
                ...validation, nameError: nameError as string, emailError: emailError as string, messageError: messageError as string, phoneError: phoneError as string
            })
            dispatch(SendConatctUsAction(contactDetail))
        }
        else {
            setValidation({
                ...validation, nameError: nameError as string, emailError: emailError as string, messageError: messageError as string, phoneError: phoneError as string
            })
        }
    }


    return (
        <Fragment>
            { loading && <Loader />}
            <Fragment>
            <div className="tab-pane fade" id="contactus" role="tabpanel" aria-labelledby="contactus-tab">
                <div className="row">
                    <div className="col-md-5 mb-md-0 mb-5">
                        <div className="contacttab-img-block">
                            <img className="img-fluid" src="images/contactus-tab-img.png" alt="" />
                        </div>

                        <ul className="list-style-none contact-list">
                            <li className="d-flex aic">
                                <span className="icon fii-call"></span>
                                <a href="tel:+01 9876543210" className="f-24 fm black-100">+01 9876543210</a>
                            </li>
                            <li className="d-flex aic">
                                <span className="icon fii-mail"></span>
                                <a href="mailto:famate@dmail.com" className="f-24 fm black-100">famate@gmail.com</a>
                            </li>
                        </ul>
                    </div>

                    <div className="col-md-7">
                        <div className="contactus-detail pl-md-5">
                            <h4 className=" f-30 fm black-100 title">Get In Touch</h4>

                            <form onSubmit={handleSubmit}>
                                <div className="row">
                                    <div className="col-12">
                                        <div className="form-group">
                                            <label className="f-20 fm black-100">Name</label>
                                            <input type="text" className={classnames("form-control", { 'is-valid': validation.nameError === false.toString() }, { 'is-invalid': validation.nameError })} placeholder="Enter Name" name="name" value={contactDetail.name} onChange={handleContact} />
                                            <p className="invalid-feedback">{validation.nameError}</p>
                                        </div>
                                    </div>

                                    <div className="col-md-6">
                                        <div className="form-group">
                                            <label className="f-20 fm black-100">Email</label>
                                            <input type="email" className={classnames("form-control", { 'is-valid': validation.emailError === false.toString() }, { 'is-invalid': validation.emailError })} placeholder="Enter Email" name="email" value={contactDetail.email} onChange={handleContact} />
                                            <p className="invalid-feedback">{validation.emailError}</p>
                                        </div>
                                    </div>

                                    <div className="col-md-6">
                                        <div className="form-group">
                                            <label className="f-20 fm black-100">Phone Number</label>
                                            <input type="text" className={classnames("form-control", { 'is-valid': validation.phoneError === false.toString() }, { 'is-invalid': validation.phoneError })} placeholder="Enter Phone Number" name="phone" value={contactDetail.phone} onChange={handleContact} />
                                            <p className="invalid-feedback">{validation.phoneError}</p>
                                        </div>
                                    </div>

                                    <div className="col-12">
                                        <div className="form-group">
                                            <label className="f-20 fm black-100">Message</label>
                                            <textarea className={classnames("form-control", { 'is-valid': validation.messageError === false.toString() }, { 'is-invalid': validation.messageError })} placeholder="Type here..." name="message" value={contactDetail.message} onChange={handleContact}></textarea>
                                            <p className="invalid-feedback">{validation.messageError}</p>
                                        </div>
                                    </div>

                                    <div className="col-12 text-center">
                                        <button type="submit" className="btn btn-lg btn-green-fill">Send</button>
                                    </div>
                                </div>

                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </Fragment>
        </Fragment>
    )
};

export default Contact;
