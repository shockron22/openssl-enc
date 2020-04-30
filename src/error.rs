use std::fmt;

#[derive(Debug, Clone)]
pub struct OpensslEncError {
    message: String,
}

impl fmt::Display for OpensslEncError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "openssl_enc error: ")
    }
}

impl From<openssl::error::ErrorStack> for OpensslEncError {
    fn from(error: openssl::error::ErrorStack) -> Self {
        OpensslEncError {
            message: error.to_string(),
        }
    }
}

impl From<&str> for OpensslEncError {
    fn from(error: &str) -> Self {
        OpensslEncError {
            message: error.to_string(),
        }
    }
}

impl OpensslEncError {
    pub fn new(msg: &str) -> OpensslEncError {
        OpensslEncError{message: msg.to_string()}
    }
}