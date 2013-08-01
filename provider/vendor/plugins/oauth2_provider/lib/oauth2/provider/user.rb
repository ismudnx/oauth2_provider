module Oauth2
  module Provider
    module User
      
      def generate_access_token (oauth_client_id)
        OauthToken.find_all_with(:user_id, id).each do |token|
          token.destroy if token.oauth_client_id == oauth_client_id
        end
        oauth_client = OauthClient.find_by_id(oauth_client_id)
        oauth_client.create_token_for_user_id(id)
      end

    end
  end
end
