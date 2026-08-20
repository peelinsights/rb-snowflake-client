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

      # Nothing to drop. The PAT was issued elsewhere and we cannot mint another, so a refused
      # one stays refused and the retry exhausts itself.
      def expire_token!
      end
    end
  end
end
