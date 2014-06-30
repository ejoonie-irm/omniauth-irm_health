require 'omniauth/strategies/oauth2'
require 'base64'
require 'openssl'
require 'rack/utils'
require 'uri'

module OmniAuth
  module Strategies
    class IrmHealth < OmniAuth::Strategies::OAuth2
      class NoAuthorizationCodeError < StandardError; end
      class UnknownSignatureAlgorithmError < NotImplementedError; end

      BASE_SCOPE_URL = 'http://auth.irm.kr' # FIXME to https
      OPHIES_BASE_URL = 'https://ophies.irm.kr'
      BASE_SCOPES = %w[email profile study series instance docset]
      DEFAULT_SCOPE = 'email'
      DEFAULT_ACCESS_TYPE = 'offline'

      option :name, 'irm_health'

      option :authorize_options, [:scope, :access_type, :state]

      option :client_options, {
        :site => BASE_SCOPE_URL,
        :authorize_url => '/o/oauth2/auth',
        :token_url => '/o/oauth2/token'
      }

      # from google oauth2
      # def authorize_params
      #     super.tab do |params|
      #         options[:authorize_options].each do |k|
      #             params[k] = request.params[k.to_s] unless [nil, ''].include? request.params[k.to_s]
      #         end
      #     end
      #
      #     raw_scope = params[:scope] || DEFAULT_SCOPE # email
      #     scope_list = raw_scope.split(" ").map {|item| item.split(",")}.flatten
      #     scope_list.map! { |s| s =~ /^http?:\/\// || BASE_SCOPES.include?(s) ? s : "#{BASE_SCOPE_URL}#{s}" }
      #     params[:scope] = scope_list.join(" ")
      #     params[:access_type] = 'offline' if params[:access_type].nil?
      #
      #     session['omniauth.state'] = params[:state] if params[:state]
      #
      # end

      # auth hash schema
      #
      # https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema

      uid { raw_info['uid'] }   # uid required

      info do                   # info required
        prune!({
            # name
            # first_name
            # last_name
            # location
            # description
            # image
            # phone
            # urls: { study: https://ophies.irm.kr/v1/studies }
          'name' => raw_info['username'],
          'email' => raw_info['email'],
          'urls' => raw_info['urls']
              # study: "https://ophies.irm.kr/v1/studies",
              # series: "https://ophies.irm.kr/v1/series",
              # instance: "https://ophies.irm.kr/v1/instances",
              # patients: "https://ophies.irm.kr/v1/patients",
              # docsets: "https://ophies.irm.kr/v1/docsets"
        })
      end


      # credentials do            # if other than those of oauth2
      #
      # end

      # no extra for irm_health
      extra do                      # provider specific info
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        @raw_info ||= access_token.get('/me').parsed
      end

      def info_options
        params = {:appsecret_proof => appsecret_proof}
        params.merge!({:fields => options[:info_fields]}) if options[:info_fields]
        params.merge!({:locale => options[:locale]}) if options[:locale]

        { :params => params }
      end

      def callback_phase
        with_authorization_code! do
          super
        end
      rescue NoAuthorizationCodeError => e
        fail!(:no_authorization_code, e)
      rescue UnknownSignatureAlgorithmError => e
        fail!(:unknown_signature_algoruthm, e)
      end

      def callback_url
        "#{OPHIES_BASE_URL}/auth/oauth2/irm_health/callback"
      end

      # def access_token_options
      #   options.access_token_options.inject({}) { |h,(k,v)| h[k.to_sym] = v; h }
      # end

      # You can pass +display+, +scope+, or +auth_type+ params to the auth request, if you need to set them dynamically.
      # You can also set these options in the OmniAuth config :authorize_params option.
      #
      # For example: /auth/facebook?display=popup
      def authorize_params
        super.tap do |params|
          BASE_SCOPES.each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end

          params[:scope] ||= DEFAULT_SCOPE
          params[:access_type] = DEFAULT_ACCESS_TYPE if params[:access_type].nil?
          session['omniauth.state'] = params[:state] if params[:state]
        end
      end


      protected


      private

      # Picks the authorization code in order, from:
      #
      # 1. The request 'code' param (manual callback from standard server-side flow)
      # 2. A signed request from cookie (passed from the client during the client-side flow)
      def with_authorization_code!
        if request.params.key?('code')
          yield
        else
          raise NoAuthorizationCodeError, 'must pass a `code`'
        end
      end

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      # def parse_signed_request(value)
      #   signature, encoded_payload = value.split('.')
      #   return if signature.nil?
      #
      #   decoded_hex_signature = base64_decode_url(signature)
      #   decoded_payload = MultiJson.decode(base64_decode_url(encoded_payload))
      #
      #   unless decoded_payload['algorithm'] == 'HMAC-SHA256'
      #     raise UnknownSignatureAlgorithmError, "unknown algorithm: #{decoded_payload['algorithm']}"
      #   end
      #
      #   if valid_signature?(client.secret, decoded_hex_signature, encoded_payload)
      #     decoded_payload
      #   end
      # end

      def valid_signature?(secret, signature, payload, algorithm = OpenSSL::Digest::SHA256.new)
        OpenSSL::HMAC.digest(algorithm, secret, payload) == signature
      end

      def base64_decode_url(value)
        value += '=' * (4 - value.size.modulo(4))
        Base64.decode64(value.tr('-_', '+/'))
      end

      # def image_url(uid, options)
      #   uri_class = options[:secure_image_url] ? URI::HTTPS : URI::HTTP
      #   url = uri_class.build({:host => 'graph.facebook.com', :path => "/#{uid}/picture"})
      #
      #   query = if options[:image_size].is_a?(String)
      #     { :type => options[:image_size] }
      #   elsif options[:image_size].is_a?(Hash)
      #     options[:image_size]
      #   end
      #   url.query = Rack::Utils.build_query(query) if query
      #
      #   url.to_s
      # end

      def appsecret_proof
        @appsecret_proof ||= OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, client.secret, access_token.token)
      end


    end
  end
end
