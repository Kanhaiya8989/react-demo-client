import {
    GET_FAQ_REQUEST, GET_FAQ_SUCCESS, GET_FAQ_FAIL,
    SEND_CONTACT_US_REQUEST, SEND_CONTACT_US_SUCCESS, SEND_CONTACT_US_FAIL
} from '../constant/HelpConstant';
import { POSTAPI, GETAPI, PUTAPI } from '../utils/ApiHelper';
import { Dispatch } from 'redux';


interface SendContactUsI {
    name: string,
    email: string,
    phone: string,
    message: string
}

export const SendConatctUsAction = (contactDetails: SendContactUsI) => async (dispatch: Dispatch) => {

    try {
        dispatch({ type: SEND_CONTACT_US_REQUEST })

        let data = await POSTAPI('save-vendor-contact-us', contactDetails);

        if (data && data.data && data.data.status) {
            dispatch({
                type: SEND_CONTACT_US_SUCCESS,
                payload: data && data.data && data.data.message
            })
        } else {
            dispatch({
                type: SEND_CONTACT_US_FAIL,
                payload: data && data.data && data.data.message
            })
        }

    } catch (error: any) {
        dispatch({
            type: SEND_CONTACT_US_FAIL,
            payload: error.message
        })

    }
}

export const GetFAQAction = () => async (dispatch: Dispatch) => {

    try {
        dispatch({ type: GET_FAQ_REQUEST })

        let data = await GETAPI('get-faqs');

        if (data && data.data && data.data.status) {
            dispatch({
                type: GET_FAQ_SUCCESS,
                payload: data && data.data && data.data.data
            })
        } else {
            dispatch({
                type: GET_FAQ_FAIL,
                payload: data && data.data && data.data.message
            })
        }

    } catch (error: any) {
        dispatch({
            type: GET_FAQ_FAIL,
            payload: error.message
        })

    }
}