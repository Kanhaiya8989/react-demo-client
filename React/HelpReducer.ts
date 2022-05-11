import {
    GET_FAQ_REQUEST, GET_FAQ_SUCCESS, GET_FAQ_FAIL,
    SEND_CONTACT_US_REQUEST, SEND_CONTACT_US_SUCCESS, SEND_CONTACT_US_FAIL
} from '../constant/HelpConstant';
import {CLEAR_ERROR, CLEAR_MESSAGE} from '../constant/VendorConstant';

export const GetFAQ = (state = { faq: null }, action: any) => {

    switch (action.type) {
        case GET_FAQ_REQUEST:
            return {
                loading: true,
                faq: null
            }
        case GET_FAQ_SUCCESS:
            return {
                loading: false,
                faq: action.payload
            }
        case GET_FAQ_FAIL:
            return {
                loading: false,
                error: action.payload
            }
        case CLEAR_ERROR:
            return {
                ...state,
                error: null
            }

        default: return state

    }
}

export const SendContactUs = (state = { contactus: null }, action: any) => {

    switch (action.type) {
        case SEND_CONTACT_US_REQUEST:
            return {
                loading: true,
                contactus: null
            }
        case SEND_CONTACT_US_SUCCESS:
            return {
                loading: false,
                contactus: action.payload
            }
        case SEND_CONTACT_US_FAIL:
            return {
                loading: false,
                error: action.payload
            }
        case CLEAR_ERROR:
            return {
                ...state,
                error: null
            }
        case CLEAR_MESSAGE:
            return {
                ...state,
                contactus: null
            }

        default: return state

    }
}