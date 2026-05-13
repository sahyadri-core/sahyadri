use sahyadri_grpc_core::protowire::{SahyadridRequest, SahyadridResponse, sahyadrid_request, sahyadrid_response};

pub(crate) trait Matcher<T> {
    fn is_matching(&self, response: T) -> bool;
}

impl Matcher<&sahyadrid_response::Payload> for sahyadrid_request::Payload {
    fn is_matching(&self, response: &sahyadrid_response::Payload) -> bool {
        use sahyadrid_request::Payload;
        match self {
            // TODO: implement for each payload variant supporting request/response pairing
            Payload::GetBlockRequest(request) => {
                if let sahyadrid_response::Payload::GetBlockResponse(response) = response {
                    if let Some(block) = response.block.as_ref() {
                        if let Some(verbose_data) = block.verbose_data.as_ref() {
                            return verbose_data.hash == request.hash;
                        }
                        return true;
                    } else if let Some(error) = response.error.as_ref() {
                        // the response error message should contain the requested hash
                        return error.message.contains(request.hash.as_str());
                    }
                }
                false
            }

            _ => true,
        }
    }
}

impl Matcher<&SahyadridResponse> for SahyadridRequest {
    fn is_matching(&self, response: &SahyadridResponse) -> bool {
        if let Some(ref response) = response.payload
            && let Some(ref request) = self.payload
        {
            return request.is_matching(response);
        }
        false
    }
}
