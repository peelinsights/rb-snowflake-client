# frozen_string_literal: true

module RubySnowflake
  class Client
    class PatAuthManager
      # a pre-issued Programmatic Access Token sent verbatim as a bearer token. No
      # X-Snowflake-Authorization-Token-Type header is set - Snowflake infers the type.
      def initialize(access_token)
        @access_token = access_token
      end

      def auth_headers
        { "Authorization" => "Bearer #{@access_token}" }
      end

      # Nothing to drop - the PAT was issued elsewhere, so a refused one stays refused.
      def expire_token!
      end
    end
  end
end
