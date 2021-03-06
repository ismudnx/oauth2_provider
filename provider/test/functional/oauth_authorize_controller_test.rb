# Copyright (c) 2010 ThoughtWorks Inc. (http://thoughtworks.com)
# Licenced under the MIT License (http://www.opensource.org/licenses/mit-license.php)
require File.join(File.dirname(__FILE__), '../test_helper')

class OauthAuthorizeControllerTest < ActionController::TestCase

  def setup
    @client = Oauth2::Provider::OauthClient.create!(:name => 'my application', :redirect_uri => 'http://example.com/cb')
    @user = User.create!(:email => 'foo@bar.com', :password => 'top-secret')
    Oauth2::Provider::Clock.fake_now = Time.utc(2008, 1, 20, 0, 0, 1)
    @old_ssl_base_url = Oauth2::Provider::Configuration.ssl_base_url
    Oauth2::Provider::Configuration.ssl_base_url = ''
  end

  def teardown
    Oauth2::Provider::Configuration.ssl_base_url = @old_ssl_base_url
    OauthAuthorizeController.allow_forgery_protection = false
    OauthAuthorizeController.request_forgery_protection_token = nil
    Oauth2::Provider::Clock.reset
  end

  def test_should_disallow_access_over_http
    session[:user_id] = @user.id

    get :index
    assert_response :forbidden

    post :authorize
    assert_response :forbidden
  end

  def test_index_contains_hidden_fields_for_client_id_and_redirect_uri_and_response_type_and_state
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'http://example.com/cb', :client_id => @client.client_id,
    :response_type => 'code', :state => 'some-state'

    assert_select '#oauth_authorize_form' do
      assert_select "#client_id[value='#{@client.client_id}']"
      assert_select "#redirect_uri[value='http://example.com/cb']"
      assert_select "#response_type[value='code']"
      assert_select "#state[value='some-state']"
    end
  end

  def test_index_contains_authenticity_token_field
    OauthAuthorizeController.allow_forgery_protection = true
    OauthAuthorizeController.request_forgery_protection_token = 'authenticity_token'
    session[:user_id] = @user.id
    session[:_csrf_token] = "csrf_token_123"

    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'http://example.com/cb', :client_id => @client.client_id,
    :response_type => 'code', :state => 'some-state'

    assert_select '#oauth_authorize_form' do
      assert_select "input[value='csrf_token_123'][name='authenticity_token']"
    end
  end

  def test_index_redirects_with_error_code_when_bogus_response_type_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'http://example.com/cb', :client_id => @client.client_id,
      :response_type => 'bogus'

    assert_redirected_to 'http://example.com/cb?error=unsupported-response-type'
  end

  def test_index_redirects_with_error_code_when_empty_response_type_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'http://example.com/cb', :client_id => @client.client_id

    assert_redirected_to 'http://example.com/cb?error=invalid-request'
  end

  def test_index_redirects_with_error_code_when_bogus_client_id_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'http://example.com/cb', :client_id => 'bogus',
      :response_type => 'code'
    assert_redirected_to 'http://example.com/cb?error=invalid-client-id'
  end

  def test_index_redirects_with_error_code_when_no_client_id_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'http://example.com/cb',
      :response_type => 'code'
    assert_redirected_to 'http://example.com/cb?error=invalid-request'
  end

  def test_index_returns_400_if_no_redirect_uri_is_supplied
    client = Oauth2::Provider::OauthClient.create!(:name => 'my application1', :redirect_uri => 'http://example.com/cba')
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :client_id => @client.client_id, :authorize => 'Yes',
      :response_type => 'code'
    assert_response :bad_request
  end

  def test_index_redirects_with_error_code_when_mismatched_uri
    client = Oauth2::Provider::OauthClient.create!(:name => 'my application1', :redirect_uri => 'http://example.com/cba')
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'bogus', :client_id => @client.client_id,
      :response_type => 'code'

    assert_redirected_to 'bogus?error=redirect-uri-mismatch'
  end

  def test_authorize_redirects_with_error_code_when_bogus_response_type_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb', :client_id => @client.client_id,
      :response_type => 'bogus'

    assert_redirected_to 'http://example.com/cb?error=unsupported-response-type'
  end

  def test_authorize_redirects_with_error_code_when_empty_response_type_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb', :client_id => @client.client_id

    assert_redirected_to 'http://example.com/cb?error=invalid-request'
  end

  def test_authorize_redirects_with_error_code_when_bogus_client_id_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb', :client_id => 'bogus',
      :response_type => 'code'
    assert_redirected_to 'http://example.com/cb?error=invalid-client-id'
  end

  def test_authorize_redirects_with_error_code_when_no_client_id_passed
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb', :response_type => 'code'
    assert_redirected_to 'http://example.com/cb?error=invalid-request'
  end

  def test_authorize_should_return_authorization_code_with_expiry_if_user_authorizes_it_and_state_param_is_not_provided
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb',
      :client_id => @client.client_id, :authorize => 'Yes', :response_type => 'code'

    assert_response :redirect
    @client.reload
    authorization = @client.oauth_authorizations.first
    assert_equal "http://example.com/cb?code=#{authorization.code}&expires_in=#{authorization.expires_in}",
      @response.redirected_to
  end

  def test_authorize_should_return_authorization_code_with_expiry_and_state_if_user_authorizes_it_and_state_param_is_provided
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb',
      :client_id => @client.client_id, :authorize => 'Yes', :response_type => 'code', :state => 'foo&bar'

    assert_response :redirect
    @client.reload
    authorization = @client.oauth_authorizations.first
    assert_equal "http://example.com/cb?code=#{authorization.code}&expires_in=#{authorization.expires_in}&state=foo%26bar",
      @response.redirected_to
  end

  def test_authorize_returns_400_if_no_redirect_uri_is_supplied
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :client_id => @client.client_id, :authorize => 'Yes', :response_type => 'code'

    assert_response 400
  end

  def test_authorize_redirects_with_error_code_when_mismatched_uri
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    get :index, :redirect_uri => 'bogus', :client_id => @client.client_id, :response_type => 'code'

    assert_redirected_to 'bogus?error=redirect-uri-mismatch'
  end

  def test_authorize_should_return_access_denied_error_if_user_does_not_authorize
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb',
      :client_id => @client.client_id, :response_type => 'code'

    assert_redirected_to 'http://example.com/cb?error=access-denied'
  end

  def test_authorize_subsequent_requests_for_authorization_code_receive_unique_codes
    session[:user_id] = @user.id
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb',
      :client_id => @client.client_id, :authorize => 'Yes', :response_type => 'code'

    auth_response_1 = @response.redirected_to

    @request = ActionController::TestRequest.new
    @request.env['HTTPS'] = "on"
    post :authorize, :redirect_uri => 'http://example.com/cb',
      :client_id => @client.client_id, :authorize => 'Yes', :response_type => 'code'

    auth_response_2 = @response.redirected_to

    assert auth_response_1 != auth_response_2
  end

end
