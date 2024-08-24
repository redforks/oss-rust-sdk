use quick_xml::{DeError, Error as QxmlError};
use reqwest::{
    header::{
        InvalidHeaderName as HttpInvalidHeaderNameError,
        InvalidHeaderValue as HttpInvalidHeaderValueError,
    },
    Error as ReqwestError,
};
use std::{error::Error as StdError, io::Error as IoError, string::FromUtf8Error};

#[derive(Debug, Display)]
pub enum Error {
    Object(ObjectError),
    Io(IoError),
    String(FromUtf8Error),
    Reqwest(ReqwestError),
    Qxml(QxmlError),
    Http(HttpError),
    DeserializeError(DeError),
}

#[derive(Debug, Display)]
pub enum HttpError {
    HttpInvalidHeaderValue(HttpInvalidHeaderValueError),
    HttpInvalidHeaderName(HttpInvalidHeaderNameError),
}

impl From<QxmlError> for Error {
    fn from(e: QxmlError) -> Error {
        Error::Qxml(e)
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Error {
        Error::Io(e)
    }
}

impl From<ReqwestError> for Error {
    fn from(e: ReqwestError) -> Error {
        Error::Reqwest(e)
    }
}

impl From<HttpInvalidHeaderValueError> for Error {
    fn from(e: HttpInvalidHeaderValueError) -> Error {
        Error::Http(HttpError::HttpInvalidHeaderValue(e))
    }
}

impl From<HttpInvalidHeaderNameError> for Error {
    fn from(e: HttpInvalidHeaderNameError) -> Error {
        Error::Http(HttpError::HttpInvalidHeaderName(e))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Error {
        Error::String(e)
    }
}

impl From<DeError> for Error {
    fn from(value: DeError) -> Error {
        Error::DeserializeError(value)
    }
}

#[derive(Debug, Display)]
pub enum ObjectError {
    #[display("PUT ERROR: {}", msg)]
    PutError { msg: String },
    #[display("GET ERROR: {}", msg)]
    GetError { msg: String },
    #[display("COPY ERROR: {}", msg)]
    CopyError { msg: String },
    #[display("DELETE ERROR: {}", msg)]
    DeleteError { msg: String },
    #[display("HEAD ERROR: {}", msg)]
    HeadError { msg: String },
    #[display("POST ERROR: {}", msg)]
    PostError { msg: String },
}

impl StdError for Error {}
